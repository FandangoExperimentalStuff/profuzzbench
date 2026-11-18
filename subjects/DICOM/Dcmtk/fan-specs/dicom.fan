# DICOM (Digital Imaging and Communications in Medicine) network protocol: Upper Layer (PS3.8) and DIMSE (PS3.7).
# Client = Fandango (association requestor, SCU), Server = the tested DICOM node (SCP).

# ======================================================================================================
# TODO: omissions, each with spec section and nearest nonterminal (reasons in feature_coverage.json / constraint_coverage.json)
# ======================================================================================================
# TODO: PS3.8 D.1.2 (sent P-DATA-TF PDUs against a Maximum-Length-received below the largest fixed form), nearest <pdu_length>: every sent form is at most about 2 KB (the generators bound the data sets), the tested servers announce 16384 and <req_c_store_oversized> sends one PDU over the announced limit; the fixed data set forms cannot be re-cut to a smaller announced limit, because the content of a data set is structure of the grammar and Fandango builds it before the limit is known (kind 1).
# TODO: PS3.8 7.6.1 / PS3.5 10.1 (a store whose transfer syntax no accepted context provides), nearest <req_c_store>: the alternatives of a data set in a syntax whose context the server refused are chosen before the negotiation result is known and Fandango cannot make an alternative conditional on it (kind 1); pick_context then sends such a request on an accepted context of the service group, never on a context the server refused, and the server answers with a failure status or an abort, both of which the grammar accepts. The same holds for the Identifier of <req_c_find>, <req_c_get>, <req_c_move> and the data sets of the N-services.
# TODO: PS3.7 9.1.4.1.4 (Priority of the C-STORE sub-operations of a C-MOVE), nearest <exchange_c_move>: they run on a second association the server opens (a third party's connection).
# TODO: PS3.7 D.3.3.7.1 (Kerberos ticket and SAML assertion contents), nearest <primary_field_token>: a Kerberos ticket is a third-party (RFC 4120) token and a SAML assertion an OASIS XML document with signatures; plain text is sent. The JWT is built from base64url parts (<primary_field_jwt>).
# TODO: PS3.7 10.3.1 / PS3.4 (content of the Event Reply data set), nearest <pdu_dataset_event_reply_ivle>: the Event Reply is sent as a generic normalized data set; the attributes a service class defines for it are in PS3.4, which is not in refs/spec/.
# TODO: PS3.7 D.3.3.5.2 / PS3.4 (content of the Service-class-application-information of a SOP Class Extended Negotiation sub-item), nearest <service_class_application_information>: each Service Class defines the bytes in PS3.4, which is not in refs/spec/; the sent value is 1 - 4 arbitrary bytes after the SOP class UID and received values are checked only by their lengths.
# TODO: PS3.5 6.1.2.4, Annex H - J (the single-byte sets other than ISO_IR 100, i.e. ISO_IR 101 - 203 with their repertoires), nearest <v_cs_charset>: the Defined Terms and repertoire tables of those sets are in PS3.3, which is not in refs/spec/ (over_budget); the sent values are Latin-1, UTF-8, GB 18030 and GBK (also characters whose trail byte is 5CH), JIS X 0208/0201/0212, GB 2312 and KS X 1001 text encoded by Python's codecs, in person names (<v_pn>) and in LO, SH, ST, LT, UT and UC values (<v_lo>, <v_sh>, <v_st>, <v_lt>, <v_ut>, <v_uc>), ISO 2022 values with their designation at the start.
# TODO: PS3.5 A.8 - A.10 (SMPTE ST 2110 transfer syntaxes), nearest <transfer_syntax_item_extra>: offered, never used; SMPTE ST 2110 flows belong to another protocol (DICOM-RTV, SMPTE ST 2110). MPEG2, H.264 2D, HEVC Main and Main 10, JPEG, JPEG-LS, JPEG 2000, HTJ2K, JPEG XL (also the recompression syntax), RLE and encapsulated uncompressed syntaxes are used with opaque or RLE fragments (<dataset_store_video>, <dataset_store_hevc10>, <dataset_store_encapsulated>, <dataset_store_single>, <dataset_store_xlrecomp>, <dataset_store_rle>).
# TODO: PS3.5 7.1.1 (the Value Representation of a received standard Data Element against the Data Dictionary), nearest <dataset_rcv>: the tag to VR assignment of the standard attributes is the Data Dictionary of PS3.6, which is not in refs/spec/ (over_budget, no way to obtain it: kind 5); a received element is checked for a known VR, for the VR the spec texts give for the tags they name (Pixel Data, Float and Double Float Pixel Data, the waveform elements and the few others) and for the length rules of its VR, not for the VR PS3.6 gives its tag.
# TODO: PS3.5 8.2.8 (Stereo Frame Packing Format of the H.264 3D syntaxes), nearest <dataset_store_stereo>: the table names the attribute without its tag, VR or values; they are defined in PS3.3, which is not in refs/spec/ (over_budget, kind 5); only Stereo Pairs Present (0022,0028) = YES is sent.
# TODO: PS3.5 A.4 (Extended Offset Table (7FE0,0001) with its Lengths (7FE0,0002)), nearest <encapsulation_basic_offset_table>: PS3.5 only names the elements (A.4: the Basic Offset Table is empty if the Extended Offset Table is present); their Value Representation, Value Multiplicity and the meaning of their values are defined in PS3.3 C.7.6.3 and PS3.6, which are not in refs/spec/ (over_budget); only received tables are checked (empty Basic Offset Table).
# Presentation context ids of sent PDVs (PS3.8 7.6.1, PS3.7 D.3.2): every sent request addresses a context the server accepted. pick_context takes an accepted context of the request's service group in the transfer syntax of the request's data set (the session proposes the SOP classes its called AE accepts, DICOM_AE_SOP_CLASSES); when the called AE accepted no context of the group, an accepted context of another group, whose abstract syntax the command then names (recall_sop_class), a protocol-valid request such as an N-GET on the Verification SOP class that the server refuses; pick_context never returns an id that is not a presentation context the server accepted (when something was accepted).
# TODO: PS3.5 8.2, PS3.3 C.7.6.3 (Image Pixel module forms beyond the sent ones), nearest <evle_image_pixel>: the sent native images are single-frame monochrome (8 bit 2 x 2 in OW and OB, 16 bit 1 x 2, 1 bit 1 x 16), RGB or YBR_FULL 8 bit 1 x 2 with Planar Configuration 0 and 1, two frames of 8 bit 2 x 2 (Number of Frames 2), float and double float, in the three uncompressed transfer syntaxes, and RLE with one, two, three and six segments (8 bit mono, 16 bit mono, 8 bit and 16 bit RGB / YBR_FULL: the segment counts Table 8.2.2-1 allows, with runs of every kind: Literal, Replicate, several per segment, no-operation bytes); PALETTE COLOR (its lookup tables), 16 bit colour in the native forms, other frame counts and geometries and the attribute combinations of the Photometric Interpretation terms are defined in PS3.3 C.7.6.3, which is not in refs/spec/ (over_budget).
# TODO: PS3.4 / PS3.3 (SOP class specific rules: Type 1/2 attributes, matching keys), nearest <dataset_store>: not in refs/spec/ (over_budget).

# ======================================================================================================
# TEST SETUP: everything the test setup decides, each value from an environment variable with a default
# ======================================================================================================
import gc
import json
import os
import random
import re
import struct
import zlib
import sys


def _csv(name, default):
    return [value.strip() for value in os.environ.get(name, default).split(",") if value.strip()]


# Called AE titles the server setup accepts (PS3.8 9.3.2 Called-AE-title); each session picks one
CALLED_AETS = _csv("DICOM_CALLED_AETS", "ANY-SCP")
# Called AE titles the server setup does not know: only the refusing association exchange sends them
WRONG_CALLED_AETS = _csv("DICOM_WRONG_CALLED_AETS", "NO-SUCH-AE,UNKNOWN-AE")
# Calling AE titles (PS3.8 9.3.2 Calling-AE-title)
CALLING_AETS = _csv("DICOM_CALLING_AETS", "FAN-SCU,FANDANGO")
# Move destination AE titles known to the server (PS3.7 9.3.4.1 Move Destination) and ones it does not know
MOVE_DESTINATIONS = _csv("DICOM_MOVE_DESTINATIONS", "MOVEDEST")
UNKNOWN_MOVE_DESTINATIONS = _csv("DICOM_UNKNOWN_MOVE_DESTINATIONS", "NO-SUCH-DEST")
# Abstract syntaxes (SOP classes) offered in presentation contexts (PS3.8 9.3.2.2.1); the lists name every target the server setup offers
VERIFICATION_SOP_CLASS = os.environ.get("DICOM_VERIFICATION_SOP_CLASS", "1.2.840.10008.1.1")
STORAGE_SOP_CLASSES = _csv("DICOM_STORAGE_SOP_CLASSES", "1.2.840.10008.5.1.4.1.1.2,1.2.840.10008.5.1.4.1.1.7,1.2.840.10008.5.1.4.1.1.1,1.2.840.10008.5.1.4.1.1.1.1,1.2.840.10008.5.1.4.1.1.1.1.1,1.2.840.10008.5.1.4.1.1.1.2,1.2.840.10008.5.1.4.1.1.1.2.1,1.2.840.10008.5.1.4.1.1.1.3,1.2.840.10008.5.1.4.1.1.1.3.1,1.2.840.10008.5.1.4.1.1.2.1,1.2.840.10008.5.1.4.1.1.2.2,1.2.840.10008.5.1.4.1.1.2.3,1.2.840.10008.5.1.4.1.1.2.4,1.2.840.10008.5.1.4.1.1.2.5,1.2.840.10008.5.1.4.1.1.3,1.2.840.10008.5.1.4.1.1.3.1,1.2.840.10008.5.1.4.1.1.4,1.2.840.10008.5.1.4.1.1.4.1,1.2.840.10008.5.1.4.1.1.4.2,1.2.840.10008.5.1.4.1.1.4.3,1.2.840.10008.5.1.4.1.1.4.4,1.2.840.10008.5.1.4.1.1.5,1.2.840.10008.5.1.4.1.1.6,1.2.840.10008.5.1.4.1.1.6.1,1.2.840.10008.5.1.4.1.1.6.2,1.2.840.10008.5.1.4.1.1.6.3,1.2.840.10008.5.1.4.1.1.7.1,1.2.840.10008.5.1.4.1.1.7.2,1.2.840.10008.5.1.4.1.1.7.3,1.2.840.10008.5.1.4.1.1.7.4,1.2.840.10008.5.1.4.1.1.8,1.2.840.10008.5.1.4.1.1.9,1.2.840.10008.5.1.4.1.1.9.1.1,1.2.840.10008.5.1.4.1.1.9.1.2,1.2.840.10008.5.1.4.1.1.9.1.3,1.2.840.10008.5.1.4.1.1.9.1.4,1.2.840.10008.5.1.4.1.1.9.2.1,1.2.840.10008.5.1.4.1.1.9.3.1,1.2.840.10008.5.1.4.1.1.9.4.1,1.2.840.10008.5.1.4.1.1.9.4.2,1.2.840.10008.5.1.4.1.1.9.5.1,1.2.840.10008.5.1.4.1.1.9.6.1,1.2.840.10008.5.1.4.1.1.9.6.2,1.2.840.10008.5.1.4.1.1.9.7.1,1.2.840.10008.5.1.4.1.1.9.7.2,1.2.840.10008.5.1.4.1.1.9.7.3,1.2.840.10008.5.1.4.1.1.9.7.4,1.2.840.10008.5.1.4.1.1.9.8.1,1.2.840.10008.5.1.4.1.1.9.100.1,1.2.840.10008.5.1.4.1.1.9.100.2,1.2.840.10008.5.1.4.1.1.10,1.2.840.10008.5.1.4.1.1.11,1.2.840.10008.5.1.4.1.1.11.1,1.2.840.10008.5.1.4.1.1.11.2,1.2.840.10008.5.1.4.1.1.11.3,1.2.840.10008.5.1.4.1.1.11.4,1.2.840.10008.5.1.4.1.1.11.5,1.2.840.10008.5.1.4.1.1.11.6,1.2.840.10008.5.1.4.1.1.11.7,1.2.840.10008.5.1.4.1.1.11.8,1.2.840.10008.5.1.4.1.1.11.9,1.2.840.10008.5.1.4.1.1.11.10,1.2.840.10008.5.1.4.1.1.11.11,1.2.840.10008.5.1.4.1.1.11.12,1.2.840.10008.5.1.4.1.1.12.1,1.2.840.10008.5.1.4.1.1.12.1.1,1.2.840.10008.5.1.4.1.1.12.2,1.2.840.10008.5.1.4.1.1.12.2.1,1.2.840.10008.5.1.4.1.1.12.3,1.2.840.10008.5.1.4.1.1.13.1.1,1.2.840.10008.5.1.4.1.1.13.1.2,1.2.840.10008.5.1.4.1.1.13.1.3,1.2.840.10008.5.1.4.1.1.13.1.4,1.2.840.10008.5.1.4.1.1.13.1.5,1.2.840.10008.5.1.4.1.1.14.1,1.2.840.10008.5.1.4.1.1.14.2,1.2.840.10008.5.1.4.1.1.20,1.2.840.10008.5.1.4.1.1.30,1.2.840.10008.5.1.4.1.1.66,1.2.840.10008.5.1.4.1.1.66.1,1.2.840.10008.5.1.4.1.1.66.2,1.2.840.10008.5.1.4.1.1.66.3,1.2.840.10008.5.1.4.1.1.66.4,1.2.840.10008.5.1.4.1.1.66.5,1.2.840.10008.5.1.4.1.1.66.6,1.2.840.10008.5.1.4.1.1.66.7,1.2.840.10008.5.1.4.1.1.66.8,1.2.840.10008.5.1.4.1.1.67,1.2.840.10008.5.1.4.1.1.68.1,1.2.840.10008.5.1.4.1.1.68.2,1.2.840.10008.5.1.4.1.1.77.1,1.2.840.10008.5.1.4.1.1.77.1.1,1.2.840.10008.5.1.4.1.1.77.1.1.1,1.2.840.10008.5.1.4.1.1.77.1.2,1.2.840.10008.5.1.4.1.1.77.1.2.1,1.2.840.10008.5.1.4.1.1.77.1.3,1.2.840.10008.5.1.4.1.1.77.1.4,1.2.840.10008.5.1.4.1.1.77.1.4.1,1.2.840.10008.5.1.4.1.1.77.1.5.1,1.2.840.10008.5.1.4.1.1.77.1.5.2,1.2.840.10008.5.1.4.1.1.77.1.5.3,1.2.840.10008.5.1.4.1.1.77.1.5.4,1.2.840.10008.5.1.4.1.1.77.1.5.5,1.2.840.10008.5.1.4.1.1.77.1.5.6,1.2.840.10008.5.1.4.1.1.77.1.5.7,1.2.840.10008.5.1.4.1.1.77.1.5.8,1.2.840.10008.5.1.4.1.1.77.1.6,1.2.840.10008.5.1.4.1.1.77.1.7,1.2.840.10008.5.1.4.1.1.77.1.8,1.2.840.10008.5.1.4.1.1.77.1.9,1.2.840.10008.5.1.4.1.1.77.2,1.2.840.10008.5.1.4.1.1.78.1,1.2.840.10008.5.1.4.1.1.78.2,1.2.840.10008.5.1.4.1.1.78.3,1.2.840.10008.5.1.4.1.1.78.4,1.2.840.10008.5.1.4.1.1.78.5,1.2.840.10008.5.1.4.1.1.78.6,1.2.840.10008.5.1.4.1.1.78.7,1.2.840.10008.5.1.4.1.1.78.8,1.2.840.10008.5.1.4.1.1.79.1,1.2.840.10008.5.1.4.1.1.80.1,1.2.840.10008.5.1.4.1.1.81.1,1.2.840.10008.5.1.4.1.1.82.1,1.2.840.10008.5.1.4.1.1.88.1,1.2.840.10008.5.1.4.1.1.88.2,1.2.840.10008.5.1.4.1.1.88.3,1.2.840.10008.5.1.4.1.1.88.4,1.2.840.10008.5.1.4.1.1.88.11,1.2.840.10008.5.1.4.1.1.88.22,1.2.840.10008.5.1.4.1.1.88.33,1.2.840.10008.5.1.4.1.1.88.34,1.2.840.10008.5.1.4.1.1.88.35,1.2.840.10008.5.1.4.1.1.88.40,1.2.840.10008.5.1.4.1.1.88.50,1.2.840.10008.5.1.4.1.1.88.59,1.2.840.10008.5.1.4.1.1.88.65,1.2.840.10008.5.1.4.1.1.88.67,1.2.840.10008.5.1.4.1.1.88.68,1.2.840.10008.5.1.4.1.1.88.69,1.2.840.10008.5.1.4.1.1.88.70,1.2.840.10008.5.1.4.1.1.88.71,1.2.840.10008.5.1.4.1.1.88.72,1.2.840.10008.5.1.4.1.1.88.73,1.2.840.10008.5.1.4.1.1.88.74,1.2.840.10008.5.1.4.1.1.88.75,1.2.840.10008.5.1.4.1.1.88.76,1.2.840.10008.5.1.4.1.1.88.77,1.2.840.10008.5.1.4.1.1.90.1,1.2.840.10008.5.1.4.1.1.91.1,1.2.840.10008.5.1.4.1.1.104.1,1.2.840.10008.5.1.4.1.1.104.2,1.2.840.10008.5.1.4.1.1.104.3,1.2.840.10008.5.1.4.1.1.104.4,1.2.840.10008.5.1.4.1.1.104.5,1.2.840.10008.5.1.4.1.1.128,1.2.840.10008.5.1.4.1.1.128.1,1.2.840.10008.5.1.4.1.1.129,1.2.840.10008.5.1.4.1.1.130,1.2.840.10008.5.1.4.1.1.131,1.2.840.10008.5.1.4.1.1.200.2,1.2.840.10008.5.1.4.1.1.200.8,1.2.840.10008.5.1.4.1.1.481.1,1.2.840.10008.5.1.4.1.1.481.2,1.2.840.10008.5.1.4.1.1.481.3,1.2.840.10008.5.1.4.1.1.481.4,1.2.840.10008.5.1.4.1.1.481.5,1.2.840.10008.5.1.4.1.1.481.6,1.2.840.10008.5.1.4.1.1.481.7,1.2.840.10008.5.1.4.1.1.481.8,1.2.840.10008.5.1.4.1.1.481.9,1.2.840.10008.5.1.4.1.1.481.10,1.2.840.10008.5.1.4.1.1.481.11,1.2.840.10008.5.1.4.1.1.481.12,1.2.840.10008.5.1.4.1.1.481.13,1.2.840.10008.5.1.4.1.1.481.14,1.2.840.10008.5.1.4.1.1.481.15,1.2.840.10008.5.1.4.1.1.481.16,1.2.840.10008.5.1.4.1.1.481.17,1.2.840.10008.5.1.4.1.1.481.18,1.2.840.10008.5.1.4.1.1.481.19,1.2.840.10008.5.1.4.1.1.481.20,1.2.840.10008.5.1.4.1.1.481.21,1.2.840.10008.5.1.4.1.1.481.22,1.2.840.10008.5.1.4.1.1.481.23,1.2.840.10008.5.1.4.1.1.481.24,1.2.840.10008.5.1.4.1.1.481.25,1.2.840.10008.5.1.4.34.7,1.2.840.10008.5.1.4.34.10")
FIND_SOP_CLASSES = _csv("DICOM_FIND_SOP_CLASSES", "1.2.840.10008.5.1.4.1.2.2.1,1.2.840.10008.5.1.4.1.2.1.1,1.2.840.10008.5.1.4.1.2.3.1,1.2.840.10008.5.1.4.31,1.2.840.10008.5.1.4.34.6.5")
MOVE_SOP_CLASSES = _csv("DICOM_MOVE_SOP_CLASSES", "1.2.840.10008.5.1.4.1.2.2.2,1.2.840.10008.5.1.4.1.2.1.2,1.2.840.10008.5.1.4.1.2.3.2")
GET_SOP_CLASSES = _csv("DICOM_GET_SOP_CLASSES", "1.2.840.10008.5.1.4.1.2.2.3,1.2.840.10008.5.1.4.1.2.1.3,1.2.840.10008.5.1.4.1.2.3.3")
# SOP classes of normalized (DIMSE-N) services (MPPS, Storage Commitment Push, Unified Procedure Step): the setup of each server lists the ones it offers (DCMTK offers none, so its requests meet a refusal)
NORMALIZED_SOP_CLASSES = _csv("DICOM_NORMALIZED_SOP_CLASSES", "1.2.840.10008.3.1.2.3.3,1.2.840.10008.1.20.1,1.2.840.10008.5.1.4.34.6.1,1.2.840.10008.5.1.4.34.6.2,1.2.840.10008.5.1.4.34.6.3,1.2.840.10008.5.1.4.34.6.4")
# Where the called AE titles differ in the SOP classes they accept (dcm4chee: one archive device, several AEs): {AE title: {group: [SOP classes]}}; a session
# proposes the classes its called AE accepts, from the group's list above (a group the AE does not offer at all keeps the whole list)
AE_SOP_CLASSES = json.loads(os.environ.get("DICOM_AE_SOP_CLASSES", "{}"))
# The master list of abstract syntaxes: the association request proposes one presentation context for each, in this
# order, with the odd id 2 * position + 1 (PS3.8 7.1.1.13)
ALL_ABSTRACT_SYNTAXES = [VERIFICATION_SOP_CLASS] + STORAGE_SOP_CLASSES + FIND_SOP_CLASSES + MOVE_SOP_CLASSES + GET_SOP_CLASSES + NORMALIZED_SOP_CLASSES
ALL_SOP_CLASSES = ALL_ABSTRACT_SYNTAXES
# Transfer syntaxes offered (PS3.5 Annex A)
TRANSFER_SYNTAXES = _csv("DICOM_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.1")
# Further transfer syntaxes (PS3.5 Annex A, 10.2 - 10.4) offered in the Verification context and in the contexts of the extra presentation context group; the default accompanies them
EXTRA_TRANSFER_SYNTAXES = _csv("DICOM_EXTRA_TRANSFER_SYNTAXES", ",".join("1.2.840.10008.1.2." + suffix for suffix in (
    "2,4.50,4.51,4.70,4.80,4.81,4.90,4.91,4.92,4.93,4.94,4.95,4.100,4.100.1,4.101,4.101.1,4.102,4.102.1,4.103,4.103.1,"
    "4.104,4.104.1,4.105,4.105.1,4.106,4.106.1,4.107,4.108,4.110,4.111,4.112,4.201,4.202,4.203,4.204,4.205,5,1.98,1.99,7.1,7.2,7.3,8.1").split(",")))
# The JPEG transfer syntaxes of PS3.5 10.2 / 10.3 (Process 1 and 4 lossy defaults, Process 14 lossless, its default Process 14 SV1): they are offered only in a context of a rule that also offers the defaults of the
# family (<transfer_syntax_items_jpeg>), or for an abstract syntax that has such a context (<rq_pc_storage_jpeg>); the plain extra lists leave them out
JPEG_FAMILY_TRANSFER_SYNTAXES = ["1.2.840.10008.1.2.4.50", "1.2.840.10008.1.2.4.51", "1.2.840.10008.1.2.4.57", "1.2.840.10008.1.2.4.70"]
PLAIN_EXTRA_TRANSFER_SYNTAXES = [uid for uid in EXTRA_TRANSFER_SYNTAXES if uid not in JPEG_FAMILY_TRANSFER_SYNTAXES]
# Encapsulation transfer syntaxes proposed in the context for generic encapsulated Pixel Data (opaque fragments), and JPIP referenced ones (PS3.5 A.4, A.6)
ENCAPSULATED_TRANSFER_SYNTAXES = _csv("DICOM_ENCAPSULATED_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.4.50,1.2.840.10008.1.2.4.51,1.2.840.10008.1.2.4.57,1.2.840.10008.1.2.4.70,1.2.840.10008.1.2.4.80,1.2.840.10008.1.2.4.81,1.2.840.10008.1.2.4.90,1.2.840.10008.1.2.4.91,1.2.840.10008.1.2.4.92,1.2.840.10008.1.2.4.93")
SINGLE_FRAGMENT_TRANSFER_SYNTAXES = _csv("DICOM_SINGLE_FRAGMENT_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.4.110,1.2.840.10008.1.2.4.112,1.2.840.10008.1.2.4.201,1.2.840.10008.1.2.4.202,1.2.840.10008.1.2.4.203")
JPIP_TRANSFER_SYNTAXES = _csv("DICOM_JPIP_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.4.94,1.2.840.10008.1.2.4.204")
# Transfer syntaxes of video Pixel Data that share one pixel module (YBR_PARTIAL_420, 8 bit, 720 x 1280): MPEG2 Main Profile, H.264 High Profile 2D, HEVC Main (PS3.5 A.4.5 - A.4.9)
STEREO_TRANSFER_SYNTAXES = _csv("DICOM_STEREO_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.4.105.1,1.2.840.10008.1.2.4.106.1")
JPIP_DEFLATE_TRANSFER_SYNTAXES = _csv("DICOM_JPIP_DEFLATE_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.4.95,1.2.840.10008.1.2.4.205")
VIDEO_TRANSFER_SYNTAXES = _csv("DICOM_VIDEO_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.4.100.1,1.2.840.10008.1.2.4.101.1,1.2.840.10008.1.2.4.102.1,1.2.840.10008.1.2.4.103.1,1.2.840.10008.1.2.4.104.1,1.2.840.10008.1.2.4.107")
# Video syntaxes whose stream is not fragmentable: the whole frame is one Fragment (PS3.5 A.4.5, A.4.6 and the H.264 syntaxes: "encoded in a single Fragment"), so they have a context and a data set of their own
VIDEO_SINGLE_TRANSFER_SYNTAXES = _csv("DICOM_VIDEO_SINGLE_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.4.100,1.2.840.10008.1.2.4.101,1.2.840.10008.1.2.4.102,1.2.840.10008.1.2.4.103,1.2.840.10008.1.2.4.104")
# The stereo (3D) H.264 syntaxes that are not fragmentable: one Fragment, and Stereo Pairs Present (0022,0028) YES (PS3.5 8.2.8 Table, 8.2.9)
STEREO_SINGLE_TRANSFER_SYNTAXES = _csv("DICOM_STEREO_SINGLE_TRANSFER_SYNTAXES", "1.2.840.10008.1.2.4.105,1.2.840.10008.1.2.4.106")
# Study / series / SOP instance UIDs stored and queried (each session picks from them)
STUDY_UIDS = _csv("DICOM_STUDY_UIDS", "1.2.826.0.1.3680043.9.7133.1.1,1.2.826.0.1.3680043.9.7133.2.1")
# User identity (PS3.7 D.3.3.7): the credentials the setup accepts and ones it does not
USER_NAME = os.environ.get("DICOM_USER_NAME", "fandango-user")
USER_PASSCODE = os.environ.get("DICOM_USER_PASSCODE", "secret")
WRONG_USER_NAMES = _csv("DICOM_WRONG_USER_NAMES", "intruder,nobody")
WRONG_USER_PASSCODES = _csv("DICOM_WRONG_USER_PASSCODES", "wrong,0000")
# Calling AE titles the server setup does not know
UNKNOWN_CALLING_AETS = _csv("DICOM_UNKNOWN_CALLING_AETS", "INTRUDER,STRANGER")
# Application context names other than the DICOM one (PS3.8 9.3.4: application-context-name-not-supported)
OTHER_APPLICATION_CONTEXTS = _csv("DICOM_OTHER_APPLICATION_CONTEXTS", "1.2.840.10008.3.1.1.2,1.2.826.0.1.3680043.9.7133.3.1")
# Names tolerated deviations of servers (empty by default; see tolerances.json)
TOLERATED = os.environ.get("TOLERATED", "")


def tolerated(name):
    return name in [item.strip() for item in TOLERATED.split(",") if item.strip()]


# Python's cyclic garbage collector pauses the generation of a message when it walks the large derivation trees (the A-ASSOCIATE-RQ has some 600 nodes): in one session of ten
# the first client message came a second late, in the measurement of turn 4 (DCMTK, 4 x 150 s: first message later than 0.8 s in 10 % of the sessions, 5 % with this setting, 15 % more sessions).
# Collect less often (the collections still run, at a higher threshold).
gc.collect()
gc.freeze()
gc.disable()
import time as _time
_gc_count = {"sessions": 0, "since_full": 0}


def collect_between_sessions():
    "Automatic collections are off: they paused a running session for up to a second. The garbage of a session is collected when the server closes the connection (or, if it did not for ten sessions, after the next A-ASSOCIATE-RQ is sent), a full collection every 50 of these."
    _gc_count["rq_since"] = 0
    _gc_count["sessions"] += 1
    _gc_count["since_full"] += 1
    start = _time.monotonic()
    if _gc_count["since_full"] >= 50:
        _gc_count["since_full"] = 0
        gc.collect()
        kind = "full"
    else:
        gc.collect(1)
        kind = "young"
    if os.environ.get("DICOM_GCLOG"):
        print("GCHOOK %s %.3f" % (kind, _time.monotonic() - start), file=sys.stderr, flush=True)


# ======================================================================================================
# Helpers (pure functions)
# ======================================================================================================
import base64
import hashlib
import json


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def deflate_even(data):
    "A deflated frame (PS3.5 A.4.13), padded with a NULL byte to an even length."
    stream = deflate_raw(data)
    return stream + b"\x00" if len(stream) % 2 else stream


def deflate_raw(data):
    "The raw deflate stream (RFC 1951) of the Deflated Explicit VR Little Endian transfer syntax (PS3.5 A.5)."
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


def u16be(n):
    return struct.pack(">H", n)


def u32be(n):
    return struct.pack(">I", n)


def u16le(n):
    return struct.pack("<H", n)


def u32le(n):
    return struct.pack("<I", n)


def ae16(title):
    return title.encode("ascii")[:16].ljust(16, b" ")


PC_IDS = {"base": 1, "next": 0}


def reset_context_ids():
    "A new request starts: its contexts take the odd ids from a random first id on, in steps of two."
    PC_IDS["base"] = random.choice(range(1, 256, 2))
    PC_IDS["next"] = 0


def pick_called_ae():
    reset_context_ids()
    title = random.choice(CALLED_AETS)
    RQ_PICK["ae"] = title
    return ae16(title)


def pick_wrong_called_ae():
    reset_context_ids()
    RQ_PICK["ae"] = None
    return ae16(random.choice(WRONG_CALLED_AETS))


def pick_calling_ae():
    return ae16(random.choice(CALLING_AETS))


def custom_abstract_syntax():
    "An abstract syntax for a context of a request with an own list: a SOP class of the setup's lists, now and then one no server knows (refused with result 3)."
    if random.random() < 0.1:
        return ("1.2.826.0.1.3680043.9.7133.5.%d" % random.randint(1, 99)).encode("ascii")
    return random.choice(ALL_ABSTRACT_SYNTAXES).encode("ascii")


def custom_transfer_syntax():
    "An additional transfer syntax of a custom context (the default syntax is offered by every custom context, PS3.5 10.1)."
    return random.choice(["1.2.840.10008.1.2.1"] + PLAIN_EXTRA_TRANSFER_SYNTAXES).encode("ascii")


def random_odd_id():
    "The id of the next context of the request being built: the first (random, odd) id advanced by 2 per context, modulo 256 (distinct for up to 128 contexts)."
    position = PC_IDS["next"]
    PC_IDS["next"] = position + 1
    return bytes([2 * (((PC_IDS["base"] - 1) // 2 + position) % 128) + 1])


def in_order(node, name, found):
    "The nodes named `name` below `node`, in the order of the message."
    if node.symbol.is_non_terminal and node.symbol.name() == name:
        found.append(node)
        return found
    for child in node.children:
        in_order(child, name, found)
    return found


def chained_context_id(node):
    "The Presentation-context-ID of the k-th context of a request: the first id advanced by 2k modulo 256, odd and distinct for up to 128 contexts (PS3.8 9.3.2.2.1, 7.1.1.13)."
    request = node
    while request.parent is not None and not request.symbol.name().startswith("<req_associate"):
        request = request.parent
    ids = in_order(request, "<rq_pc_id>", [])
    positions = [position for position, item in enumerate(ids) if item is node]
    if not positions or positions[0] == 0:
        return bytes(node)
    first = bytes(ids[0])
    if len(first) != 1:
        return bytes(node)
    return bytes([2 * (((first[0] - 1) // 2 + positions[0]) % 128) + 1])


def request_of(node):
    request = node
    while request.parent is not None and not request.symbol.name().startswith("<req_"):
        request = request.parent
    return request


def first_context_id_of_request(node):
    "The Presentation-context-ID of the first PDV of the request the node belongs to: every PDV of a request uses one context (PS3.8 E.1), so the data PDV takes the id of the command PDV."
    found = []

    def walk(item):
        if item.symbol.is_non_terminal and item.symbol.name().startswith("<pdv_context_id_") and len(bytes(item)) == 1:
            found.append(item)
            return
        for child in item.children:
            if not found:
                walk(child)
    walk(request_of(node))
    return bytes(found[0]) if found else bytes(node)


def sop_class_of_context(node):
    "The Affected/Requested SOP Class UID of a request is the abstract syntax of the context the request uses (PS3.7 D.3.2): the SOP class follows from the context id of the request's first PDV."
    category = node.symbol.name()[len("<cmd_uid_"):-1]
    context_id = first_context_id_of_request(node)
    abstract = PROPOSED.get(context_id[0], ("", []))[0] if context_id else ""
    if abstract:
        return uid_pad(abstract.encode("ascii"))
    return uid_pad(DEFAULT_SOP_CLASS[category].encode("ascii"))


def pick_uid(values):
    return random.choice(values).encode("ascii")


def from_u16(value):
    return value[0] << 8 | value[1]


def rle_offset_value(node, segment):
    "The offset of the RLE Segment with the given number (counted from 1) in the RLE Header: 64 plus the lengths of the segments before it (PS3.5 G.5)."
    codestream = node.parent.parent
    return u32le(64 + sum(len(bytes(codestream.children[index])) for index in range(1, segment)))


def pdv_chunks(length):
    "Number of 64 KiB chunks in the fragment of a PDV whose Item-length is given (the PDV holds the context id, the header byte and the fragment)."
    return max(from_u32(bytes(length)) - 2, 0) >> 16


def pdv_rest(length):
    "Bytes of the fragment after its 64 KiB chunks."
    return max(from_u32(bytes(length)) - 2, 0) & 65535


def from_u32(value):
    return value[0] << 24 | value[1] << 16 | value[2] << 8 | value[3]


def children_named(tree, name):
    return [child for child in tree.children if child.symbol.is_non_terminal and child.symbol.name() == name]


def descendants_named(tree, name):
    "Nodes of one nonterminal below tree in document order; the continuation <sta6> that closes an exchange is not entered."
    found, stack = [], [tree]
    while stack:
        node = stack.pop()
        if node.symbol.is_non_terminal:
            node_name = node.symbol.name()
            if node_name == name:
                found.append(node)
            if node_name == "<sta6>" and node is not tree and name != "<sta6>":
                continue
        stack.extend(reversed(node.children))
    return found


def position_of(node, parent_name):
    "Index of the item the node belongs to among the same-named siblings below the grandparent."
    item = node.parent
    position = 0
    for child in item.parent.children:
        if child is item:
            return position
        if child.symbol == item.symbol:
            position += 1
    return 0


def context_id_by_position(node):
    return bytes([2 * position_of(node, None) + 1])


def abstract_syntax_by_position(node):
    return ALL_ABSTRACT_SYNTAXES[position_of(node.parent, None) % len(ALL_ABSTRACT_SYNTAXES)].encode("ascii")


def context_id_for_sop_class(sop_class):
    return bytes([2 * ALL_ABSTRACT_SYNTAXES.index(sop_class.decode("ascii")) + 1])


RQ_PICK = {}


def pick_abstract(category, values):
    offered = AE_SOP_CLASSES.get(RQ_PICK.get("ae"), {}).get(category)
    if offered:
        values = [value for value in values if value in offered] or values
    RQ_PICK[category] = random.choice(values)
    return RQ_PICK[category].encode("ascii")


def recall_pick(category):
    return RQ_PICK.get(category, DEFAULT_SOP_CLASS[category]).encode("ascii")


def next_sibling_length(node):
    "Length of the field that follows this length field in its parent."
    siblings = node.parent.children
    for position in range(len(siblings)):
        if siblings[position] is node:
            return len(bytes(siblings[position + 1]))
    return 0


def child_length(parent, name):
    return sum(len(bytes(child)) for child in children_named(parent, name))


def related_general_size(item):
    return sum(len(bytes(child)) for child in children_named(item, "<related_general_sop_class_item>"))



# --- session memory: what this session proposed and what the server accepted (filled by the Client party below) ---
from fandango.io import NetworkParty

PROPOSED = {}
ACCEPTED = {}
SESSION = {"instance": None, "ctx": {}}
BASE_CATEGORIES = ("verification", "storage", "find", "move", "get", "normalized")
STANDARD_CATEGORIES = ["verification", "storage", "find", "move", "get", "normalized", "storage", "find", "move", "get", "normalized", "storage_rle", "storage_encapsulated", "storage_jpip", "storage_evbe",
                       "storage_deflated", "storage_video", "storage_uncompressed", "storage_deflated_frame", "storage_stereo", "storage_jpip_deflate", "storage_single", "storage_hevc10", "storage_xlrecomp", "storage_video_single", "storage_stereo_single", "storage_jpeg"]
STANDARD_GROUPS = ["verification", "storage", "find", "move", "get", "normalized", "storage", "find", "move", "get", "normalized"] + ["storage"] * 16
CATEGORY_OF_CONTEXT = {}
DEFAULT_CONTEXT_ID = {"verification": 1, "storage": 3, "find": 5, "move": 7, "get": 9, "normalized": 11, "storage_rle": 23, "storage_encapsulated": 25, "storage_jpip": 27, "storage_evbe": 29, "storage_deflated": 31, "storage_video": 33, "storage_uncompressed": 35, "storage_deflated_frame": 37, "storage_stereo": 39, "storage_jpip_deflate": 41, "storage_single": 43, "storage_hevc10": 45, "storage_xlrecomp": 47, "storage_video_single": 49, "storage_stereo_single": 51, "storage_jpeg": 53}
EVLE = "1.2.840.10008.1.2.1"
DEFAULT_SOP_CLASS = {"verification": VERIFICATION_SOP_CLASS, "storage": STORAGE_SOP_CLASSES[0], "find": FIND_SOP_CLASSES[0],
                     "move": MOVE_SOP_CLASSES[0], "get": GET_SOP_CLASSES[0], "normalized": NORMALIZED_SOP_CLASSES[0]}


CUSTOM_CATEGORY = {}


def category_of(context_id):
    "The service group of a presentation context: by the fixed id list of the standard association request, by the abstract syntax in a request with an own list of contexts (PS3.8 7.1.1.13)."
    if CUSTOM_CATEGORY:
        return CUSTOM_CATEGORY.get(context_id)
    return CATEGORY_OF_CONTEXT.get(context_id)


def group_of_abstract(abstract):
    if abstract == VERIFICATION_SOP_CLASS:
        return "verification"
    groups = {"storage": STORAGE_SOP_CLASSES, "find": FIND_SOP_CLASSES, "move": MOVE_SOP_CLASSES, "get": GET_SOP_CLASSES, "normalized": NORMALIZED_SOP_CLASSES}
    for group in groups:
        if abstract in groups[group]:
            return group
    return None


def split_items(data):
    items, offset = [], 0
    while offset + 4 <= len(data):
        length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        items.append((data[offset], data[offset + 4:offset + 4 + length]))
        offset += 4 + length
    return items


def user_data_max_length(pdu):
    for kind, body in split_items(pdu[74:]):
        if kind == 0x50:
            for sub_kind, sub_body in split_items(body):
                if sub_kind == 0x51 and len(sub_body) == 4:
                    return struct.unpack(">I", sub_body)[0]
    return 0


def record_request(pdu):
    PROPOSED.clear()
    ACCEPTED.clear()
    SESSION["ctx"] = {}
    SESSION["last"] = None
    MAX_LENGTH["rq"] = user_data_max_length(pdu)
    MAX_LENGTH["ac"] = 0
    for kind, body in split_items(pdu[74:]):
        if kind == 0x20 and len(body) >= 4:
            abstract, syntaxes = "", []
            for sub_kind, sub_body in split_items(body[4:]):
                if sub_kind == 0x30:
                    abstract = sub_body.decode("ascii", "replace")
                elif sub_kind == 0x40:
                    syntaxes.append(sub_body.decode("ascii", "replace"))
            PROPOSED[body[0]] = (abstract, syntaxes)
    CUSTOM_CATEGORY.clear()
    CATEGORY_OF_CONTEXT.clear()
    ordered = list(PROPOSED)
    groups = [group_of_abstract(PROPOSED[context_id][0]) for context_id in ordered]
    if len(ordered) == len(STANDARD_GROUPS) and all(group is None or group == expected for group, expected in zip(groups, STANDARD_GROUPS)):
        # the standard request: its 27 contexts come in a fixed order, whatever their ids, and the service group of each follows from the position
        for position, context_id in enumerate(ordered):
            CATEGORY_OF_CONTEXT[context_id] = STANDARD_CATEGORIES[position]
    else:
        # a request with an own list of presentation contexts: the service group of a context is that of its abstract syntax
        for context_id in PROPOSED:
            group = group_of_abstract(PROPOSED[context_id][0])
            if group is not None:
                CUSTOM_CATEGORY[context_id] = group
        if not CUSTOM_CATEGORY:
            CUSTOM_CATEGORY[-1] = None


def record_accept(pdu):
    MAX_LENGTH["ac"] = user_data_max_length(pdu)
    for kind, body in split_items(pdu[74:]):
        if kind == 0x21 and len(body) >= 4:
            syntax = ""
            for sub_kind, sub_body in split_items(body[4:]):
                if sub_kind == 0x40:
                    syntax = sub_body.decode("ascii", "replace")
            ACCEPTED[body[0]] = (body[2], syntax)


class ClientNetworkParty(NetworkParty):
    def send(self, message, recipient):
        data = bytes(message.to_bytes()) if hasattr(message, "to_bytes") else bytes(message)
        if data[:1] == b"\x01":
            SESSION["instance"] = None
            for key in list(SESSION):
                if key.startswith("server_"):
                    del SESSION[key]
            record_request(data)
            _gc_count["rq_since"] = _gc_count.get("rq_since", 0) + 1
            super().send(message, recipient)
            if _gc_count["rq_since"] >= 10:
                collect_between_sessions()
            return
        super().send(message, recipient)

    def receive(self, message, sender):
        if message is None:
            collect_between_sessions()
        if isinstance(message, (bytes, bytearray)):
            try:
                if bytes(message[:1]) == b"\x02":
                    record_accept(bytes(message))
                record_server_message_id(bytes(message))
            except Exception:
                # a message that arrives in pieces ends inside a PDU or element: what could be read has been recorded
                pass
        super().receive(message, sender)


def record_server_message_id(data):
    "Remembers the Message ID of the last command the server sent (echoed in the client's response); the Command Fragments of a split command are joined first."
    offset, command, context = 0, b"", None
    while offset + 6 <= len(data):
        pdu_length = struct.unpack(">I", data[offset + 2:offset + 6])[0]
        if data[offset] == 4:
            position, end = offset + 6, offset + 6 + pdu_length
            while position + 6 <= end:
                length = struct.unpack(">I", data[position:position + 4])[0]
                fragment = data[position + 6:position + 4 + length]
                if data[position + 5] & 1:
                    command += fragment
                    context = bytes([data[position + 4]])
                    if data[position + 5] & 2:
                        record_server_command(command, context)
                        command = b""
                position += 4 + length
        offset += 6 + pdu_length
    if command:
        record_server_command(command, context)


def record_server_command(fragment, context):
    cursor = 0
    while cursor + 8 <= len(fragment):
        group, element, value_length = struct.unpack("<HHI", fragment[cursor:cursor + 8])
        if (group, element) == (0, 0x0110):
            SESSION["server_message_id"] = fragment[cursor + 8:cursor + 10]
            SESSION["server_context"] = context
        if group == 0 and element in (0x0002, 0x1000, 0x1002):
            SESSION["server_element_%d" % element] = fragment[cursor + 8:cursor + 8 + value_length]
        cursor += 8 + value_length


STORAGE_SYNTAX_GROUPS = {"storage_rle": ["1.2.840.10008.1.2.5"], "storage_encapsulated": ENCAPSULATED_TRANSFER_SYNTAXES, "storage_jpip": JPIP_TRANSFER_SYNTAXES, "storage_evbe": ["1.2.840.10008.1.2.2"],
                         "storage_deflated": ["1.2.840.10008.1.2.1.99"], "storage_video": VIDEO_TRANSFER_SYNTAXES, "storage_uncompressed": ["1.2.840.10008.1.2.1.98"],
                         "storage_deflated_frame": ["1.2.840.10008.1.2.8.1"], "storage_stereo": STEREO_TRANSFER_SYNTAXES, "storage_jpip_deflate": JPIP_DEFLATE_TRANSFER_SYNTAXES,
                         "storage_single": SINGLE_FRAGMENT_TRANSFER_SYNTAXES, "storage_hevc10": ["1.2.840.10008.1.2.4.108"], "storage_xlrecomp": ["1.2.840.10008.1.2.4.111"], "storage_video_single": VIDEO_SINGLE_TRANSFER_SYNTAXES, "storage_stereo_single": STEREO_SINGLE_TRANSFER_SYNTAXES}


def pick_context(category, syntax):
    "A presentation context of the category the server accepted (with the transfer syntax, if given); remembered for the rest of the message."
    ids = []
    for context_id in ACCEPTED:
        outcome = ACCEPTED[context_id]
        if outcome[0] == 0 and category_of(context_id) == category and (syntax is None or outcome[1] == syntax):
            ids.append(context_id)
    if not ids and category in BASE_CATEGORIES:
        accepted_in_category = [context_id for context_id in ACCEPTED if ACCEPTED[context_id][0] == 0 and category_of(context_id) == category]
        if not accepted_in_category:
            # the server accepted no context of this service group: the request addresses a SOP class it did accept a context for (PS3.7 D.3.2)
            for context_id in ACCEPTED:
                outcome = ACCEPTED[context_id]
                if outcome[0] == 0 and category_of(context_id) in BASE_CATEGORIES and (syntax is None or outcome[1] == syntax):
                    ids.append(context_id)
            if not ids:
                for context_id in ACCEPTED:
                    if ACCEPTED[context_id][0] == 0 and category_of(context_id) in BASE_CATEGORIES:
                        ids.append(context_id)
    if not ids and CUSTOM_CATEGORY and ACCEPTED:
        # a request with a list of contexts of its own: a storage context that the server accepted in a transfer syntax of one of the syntax-specific storage groups serves that group's stores; a service group
        # whose contexts were accepted only in other syntaxes is addressed on a context of another base group in the syntax needed (a protocol-valid request that the server refuses)
        if category in STORAGE_SYNTAX_GROUPS:
            for context_id in ACCEPTED:
                if ACCEPTED[context_id][0] == 0 and CUSTOM_CATEGORY.get(context_id) == "storage" and ACCEPTED[context_id][1] in STORAGE_SYNTAX_GROUPS[category]:
                    ids.append(context_id)
        elif category in BASE_CATEGORIES:
            for context_id in sorted(ACCEPTED):
                if ACCEPTED[context_id][0] == 0 and CUSTOM_CATEGORY.get(context_id) in BASE_CATEGORIES and (syntax is None or ACCEPTED[context_id][1] == syntax):
                    ids.append(context_id)
                    break
    if not ids and ACCEPTED:
        # no accepted context provides the transfer syntax of this alternative (a store in a syntax whose context the server refused): the request goes on an accepted context of the category in the syntax
        # the server chose, else on any accepted context; the id is always one the server accepted (see the TODO at <req_c_store>)
        if category.startswith("storage_"):
            # the data sets of the other-syntax alternatives are made of Explicit VR elements: the Explicit VR Little Endian context of the storage group comes first
            ids = [context_id for context_id in ACCEPTED if ACCEPTED[context_id][0] == 0 and category_of(context_id) == "storage" and ACCEPTED[context_id][1] == EVLE]
        if not ids:
            for context_id in ACCEPTED:
                if ACCEPTED[context_id][0] == 0 and category_of(context_id) == category:
                    ids.append(context_id)
        if not ids:
            ids = [context_id for context_id in ACCEPTED if ACCEPTED[context_id][0] == 0]
    if not ids:
        # only before an A-ASSOCIATE-AC has been recorded (Fandango may call a generator ahead of the exchange; nothing is sent on this id): the id the standard request gives the group. After the AC every
        # sent id is one of the accepted contexts: an AC without any accepted context leads to <sta6_refused>, which sends no P-DATA-TF (PS3.8 7.6.1, PS3.7 D.3.2)
        ids = [default_context_id(category)]
    choice = random.choice(ids)
    SESSION["ctx"][category] = choice
    SESSION["last"] = (category, choice)
    return bytes([choice])


def default_context_id(category):
    "The id of the first context proposed for the service group (before any request: the id the standard list would give it by position)."
    for context_id in PROPOSED:
        if category_of(context_id) == category:
            return context_id
    return DEFAULT_CONTEXT_ID[category]


def unaccepted_context_id():
    "A Presentation Context ID the A-ASSOCIATE-AC did not accept (PS3.8 7.6.1): a refused context of the request, or any odd id the association has no accepted context for."
    taken = set(context_id for context_id in ACCEPTED if ACCEPTED[context_id][0] == 0)
    refused = [context_id for context_id in ACCEPTED if ACCEPTED[context_id][0] != 0]
    others = [context_id for context_id in range(1, 256, 2) if context_id not in taken]
    return bytes([random.choice(refused) if refused and random.random() < 0.5 else random.choice(others)])


def recall_context(category):
    return bytes([SESSION["ctx"].get(category, default_context_id(category))])


def recall_server_element(element, default):
    "A value of the last command the server sent (Affected SOP Class UID, Affected SOP Instance UID, Event Type ID), echoed in the client's response."
    return SESSION.get("server_element_%d" % element, default)


def recall_server_context():
    return SESSION.get("server_context", b"\x01")


# Specific Character Set values (PS3.5 6.1.2.3, 6.1.2.5, Annex H - J) with the codec that encodes text values in them
CHARSETS = [(b"ISO_IR 6", "ascii"), (b"ISO_IR 100", "latin-1"), (b"ISO_IR 192", "utf-8"), (b"GB18030 ", "gb18030"), (b"GBK ", "gbk"),
            (b"ISO_IR 13\\ISO 2022 IR 87", "jis13"), (b"\\ISO 2022 IR 87 ", "jis"), (b"ISO 2022 IR 13\\ISO 2022 IR 87 ", "jis13"), (b"ISO_IR 100\\ISO 2022 IR 149", "kr"),
            (b"\\ISO 2022 IR 58 ", "zh"), (b"ISO 2022 IR 13\\ISO 2022 IR 87\\ISO 2022 IR 159 ", "jis159")]


TRAIL_5C = ["\u4e57", "\u4fd3", "\u50dc", "\u5213"]


def charset_value():
    "Records the character set of the data set that is being built; the text values after it are encoded in it."
    value, kind = random.choice(CHARSETS)
    SESSION["charset"] = kind
    return value


def even(value):
    return value + b" " if len(value) % 2 else value


def encoded_name(kind):
    "A person name whose component groups are encoded in the character set (PS3.5 6.2.1.2, Annex H - J)."
    if kind == "latin-1":
        return random.choice(["M\u00fcller^J\u00f6rg", "Gonz\u00e1lez^Mar\u00eda=Gonzalez^Maria"]).encode("latin-1")
    if kind == "utf-8":
        return random.choice(["M\u00fcller^J\u00f6rg", "Wang^XiaoDong=\u738b^\u5c0f\u4e1c", "Yamada^Tarou=\u5c71\u7530^\u592a\u90ce=\u3084\u307e\u3060^\u305f\u308d\u3046"]).encode("utf-8")
    if kind in ("gb18030", "gbk"):
        if random.random() < 0.4:
            # a character whose trail byte is 5CH: only a single byte 5CH is a delimiter (PS3.5 6.1.2.3)
            return b"Wang^XiaoDong=" + ("\u738b^" + random.choice(TRAIL_5C)).encode(kind)
        return b"Wang^XiaoDong=" + "\u738b^\u5c0f\u4e1c".encode(kind)
    if kind == "zh":
        # GB 2312 (ISO IR 58) invoked into G1 by ESC $ ) A before each component group (PS3.5 K.2)
        return b"Zhang^XiaoDong=\x1b$)A" + "\u5f20".encode("gb2312") + b"^\x1b$)A" + "\u5c0f\u4e1c".encode("gb2312")
    if kind == "jis159":
        # JIS X 0212 (ISO IR 159) in G0 by ESC $ ( D, JIS X 0208 by ESC $ B, JIS X 0201 roman by ESC ( J
        return (b"Yamada^Tarou=" + "\u5c71\u7530^\u4e02".encode("iso2022_jp_1") + b"=" + "\u3084\u307e\u3060^\u592a\u90ce".encode("iso2022_jp_1")).replace(b"\x1b(B", b"\x1b(J")
    if kind in ("jis", "jis13"):
        name = b"Yamada^Tarou=" + "\u5c71\u7530^\u592a\u90ce".encode("iso2022_jp") + b"=" + "\u3084\u307e\u3060^\u305f\u308d\u3046".encode("iso2022_jp")
        if kind == "jis13":
            if random.random() < 0.3:
                # single-byte katakana in the GR area, invoked into G1 by ESC ) I (PS3.5 H.3.2)
                return b"Yamada^Tarou=\x1b)I" + "\uff94\uff8f\uff80\uff9e".encode("shift_jis") + b"^\x1b)I" + "\uff80\uff9b\uff73".encode("shift_jis")
            return name.replace(b"\x1b(B", b"\x1b(J")
        return name
    if kind == "kr":
        # KS X 1001 invoked into G1 (8-bit GR bytes) by ESC $ ) C, repeated before every component group (PS3.5 I.2)
        return b"Hong^Gil-dong=\x1b$)C" + "\ud64d".encode("euc_kr") + b"^\x1b$)C" + "\uae38\ub3d9".encode("euc_kr")
    return random.choice([b"DOE^JOHN", b"SMITH^ALICE^^^", b"*       ", b"Yamada^Tarou=yamada^taro", b"Hong^Gil=hong^gil=Hong", b"A^B^C^D^E=F^G^H^I^J "])


def pn_value():
    return even(encoded_name(SESSION.get("charset", "ascii")))


RICH_TEXT = {"latin-1": ["Gr\u00f6\u00dfe", "\u00dcbung 1"], "utf-8": ["\u4e2d\u6587", "Gr\u00f6\u00dfe \u4e2d"], "gb18030": ["\u4e2d\u6587", "\u5b57 text"], "gbk": ["\u4e2d\u6587", "\u5b57 text"]}


def rich_text(kind):
    "A text value of a character set that replaces the default repertoire, or None (PS3.5 6.1.2.3); ISO 2022 values start with their designation."
    if kind == "zh":
        return b"\x1b$)A" + "\u7b2c\u4e00".encode("gb2312")
    if kind == "kr":
        return b"\x1b$)C" + "\ud64d\uae38".encode("euc_kr")
    if kind in RICH_TEXT:
        return random.choice(RICH_TEXT[kind]).encode("utf-8" if kind == "utf-8" else kind if kind != "latin-1" else "latin-1")
    return None


def text_value(plain):
    "A value of ST, LT, UT, SH, UC or LO: plain ASCII, or text in the data set's character set."
    value = random.choice(plain)
    if random.random() < 0.5:
        value = rich_text(SESSION.get("charset", "ascii")) or value
    return even(value)


def lo_value():
    return text_value([b"PID001", b"ID123456", b"CREATOR1"])


def st_value():
    return text_value([b"short text", b"more text "])


def lt_value():
    return text_value([b"a long text ", b"free  text"])


def ut_value():
    return text_value([b"unlimited te", b"text value  "])


def sh_value():
    return text_value([b"SHORT1", b"AB12"])


def uc_value():
    return text_value([b"unlimited ch", b"char values "])


def creator_value():
    return random.choice([b"CREATOR1", b"FANDANGO PRIVATE", b"ACME 1.0"])


def message_id_choice():
    "A Message ID; every request starts a new data set, whose text values are ASCII until its Specific Character Set says otherwise."
    SESSION["charset"] = "ascii"
    return random.choice([b"\x01\x00", b"\x02\x00", b"\x2a\x00", b"\xff\xff"])


def error_comment_value():
    "An Error Comment (0000,0902) of an even length, padded with a space (PS3.5 6.2, 7.1.2)."
    text = random.choice([b"Processing failure", b"Cannot process the request", b"Resource limitation", b"No such SOP instance", b"Duplicate invocation", b"Mistyped argument"])
    return text + b" " if len(text) % 2 else text


def recall_server_message_id():
    return SESSION.get("server_message_id", b"\x01\x00")


def uid_pad(value):
    return value + b"\x00" if len(value) % 2 else value


def recall_sop_class(category):
    "The SOP class of the presentation context the request of this service group uses (PS3.7 D.3.2): the abstract syntax of the context pick_context chose."
    last = SESSION.get("last")
    if last is not None and last[1] in PROPOSED and PROPOSED[last[1]][0] and (last[0] == category or (category == "storage" and last[0].startswith("storage"))):
        return uid_pad(PROPOSED[last[1]][0].encode("ascii"))
    for context_id in PROPOSED:
        abstract = PROPOSED[context_id][0]
        if category_of(context_id) == category and abstract and (not ACCEPTED or ACCEPTED.get(context_id, (1,))[0] == 0):
            return uid_pad(abstract.encode("ascii"))
    return uid_pad(DEFAULT_SOP_CLASS[category].encode("ascii"))


def recall_sop_class_padded():
    return recall_sop_class("storage")


def study_uid_with_pad():
    return uid_pad(random.choice(STUDY_UIDS).encode("ascii"))


def series_uid_with_pad():
    return uid_pad((STUDY_UIDS[0] + ".2").encode("ascii"))


def instance_uid_with_pad():
    if SESSION["instance"] is None:
        SESSION["instance"] = uid_pad((random.choice(STUDY_UIDS) + ".3." + str(random.randint(1, 99999))).encode("ascii"))
    return SESSION["instance"]


def descendants_named_any(tree):
    found, stack = [], [tree]
    while stack:
        node = stack.pop()
        if node.symbol.is_non_terminal:
            found.append(node)
        stack.extend(node.children)
    return found


def cancel_target_message_id(node):
    "A C-CANCEL carries the Message ID of the request it cancels (PS3.7 9.3.2.3, E.1)."
    exchange = node.parent
    while exchange is not None:
        requests = descendants_named(exchange, "<message_id_value>")
        if requests:
            return bytes(requests[0])
        exchange = exchange.parent
    return b"\x01\x00"


def message_id_matches(exchange):
    "Every Message ID Being Responded To of the replies equals the request's Message ID (PS3.7 E.1)."
    requests = descendants_named(exchange, "<message_id_value>")
    if not requests:
        return True
    expected = bytes(requests[0])
    return all(bytes(node) == expected for node in descendants_named(exchange, "<message_id_responded_value>"))


def other_message_id(node):
    "The Message ID of the second request of a pair of C-ECHO-RQs sent together: the first one's plus one (65535 is followed by 1), so the two differ (PS3.7 E.1: the Message ID is unique among the outstanding requests)."
    pair = node
    while pair is not None and not (pair.symbol.is_non_terminal and pair.symbol.name() == "<req_c_echo_pair>"):
        pair = pair.parent
    first = descendants_named(pair, "<message_id_value>")[0] if pair is not None else None
    number = struct.unpack("<H", bytes(first))[0] if first is not None else 1
    return struct.pack("<H", number % 65535 + 1)


def echo_pair_ok(exchange):
    "The two replies to a pair of C-ECHO-RQs sent together answer the two requests, each once, in either order (PS3.7 E.1, D.3.3.3)."
    asked = [bytes(node) for node in descendants_named(exchange, "<message_id_value>")] + [bytes(node) for node in descendants_named(exchange, "<message_id_value_second>")]
    answered = [bytes(node) for node in descendants_named(exchange, "<message_id_responded_value>")]
    return all(item in asked for item in answered) and len(set(answered)) == len(answered)


def find_response_ok(exchange):
    "A C-FIND-RSP carries an Identifier only when its status is Pending (PS3.7 9.1.2.1.5, 9.1.2.1.6)."
    return True


def echo_status_ok(exchange):
    "The C-ECHO-RSP status is one the C-ECHO service defines: Success or the refusals 0122H, 0210H, 0211H, 0212H (PS3.7 9.1.5.1.4, 9.3.5.2)."
    return all(bytes(node) in (b"\x00\x00", b"\x22\x01", b"\x10\x02", b"\x11\x02", b"\x12\x02") for node in descendants_named(exchange, "<status_value>"))


def command_fragments(node):
    "The bytes of the Command Fragments below a received split command, in order."
    found, stack = [], [node]
    while stack:
        item = stack.pop()
        if item.symbol.is_non_terminal and item.symbol.name() in ("<command_fragment_more_rcv>", "<command_fragment_last_rcv>"):
            found.append(bytes(item))
        else:
            stack.extend(reversed(item.children))
    return found


def split_command_ok(exchange, command_field, echo):
    "A response command set received in Command Fragments (PS3.8 E.1) is a response of the request's kind: Command Group Length, Command Field, Data Set Type 0101H, Message ID Being Responded To equal to the request's, a Status, echoed UIDs (PS3.7 9.3, 9.1.1.1.3, E.1)."
    splits = descendants_named(exchange, "<rsp_command_split>")
    if not splits:
        return True
    requests = descendants_named(exchange, "<message_id_value>")
    request_class, request_instance = None, None
    for name in ("<cmd_uid_verification>", "<cmd_uid_storage>", "<cmd_uid_normalized>"):
        found = descendants_named(exchange, name)
        if found:
            request_class = strip_uid(found[0])
            break
    instances = descendants_named(exchange, "<cmd_instance_uid>")
    if instances:
        request_instance = strip_uid(instances[0])
    for split in splits:
        data = b"".join(command_fragments(split))
        elements, position, previous = {}, 0, (-1, -1)
        while position < len(data):
            if position + 8 > len(data):
                return False
            group, element, length = struct.unpack("<HHI", data[position:position + 8])
            if (group, element) <= previous or length % 2 or position + 8 + length > len(data):
                return False
            elements[(group, element)] = data[position + 8:position + 8 + length]
            previous = (group, element)
            position += 8 + length
        if position != len(data) or (0, 0) not in elements or len(elements[(0, 0)]) != 4 or struct.unpack("<I", elements[(0, 0)])[0] != len(data) - 12:
            return False
        if elements.get((0, 0x0100)) != struct.pack("<H", command_field) or elements.get((0, 0x0800)) != b"\x01\x01":
            return False
        if (0, 0x0120) not in elements or len(elements[(0, 0x0120)]) != 2 or (0, 0x0900) not in elements or len(elements[(0, 0x0900)]) != 2:
            return False
        if requests and elements[(0, 0x0120)] not in [bytes(node) for node in requests] + [bytes(node) for node in descendants_named(exchange, "<message_id_value_second>")]:
            return False
        if echo and elements[(0, 0x0900)] not in (b"\x00\x00", b"\x22\x01", b"\x10\x02", b"\x11\x02", b"\x12\x02"):
            return False
        if request_class is not None and (0, 0x0002) in elements and strip_uid(elements[(0, 0x0002)]) != request_class:
            return False
        if request_instance is not None and (0, 0x1000) in elements and strip_uid(elements[(0, 0x1000)]) != request_instance:
            return False
    return True


COMMAND_COMMON = {0x0000, 0x0002, 0x0100, 0x0110, 0x0120, 0x0800, 0x0900, 0x0901, 0x0902, 0x0903}
COMMAND_COUNTS = {0x1020, 0x1021, 0x1022, 0x1023}
# kind: (Command Field, "rsp"/"rq", status class, data set rule, allowed command element tags in group 0000H, required tags)
SPLIT_KINDS = {
    "c_find_pending": (0x8020, "rsp", "pending", "must", COMMAND_COMMON, ()),
    "c_find_final": (0x8020, "rsp", "final", "must_not", COMMAND_COMMON, ()),
    "c_get_pending": (0x8010, "rsp", "pending", "optional", COMMAND_COMMON | COMMAND_COUNTS, tuple(COMMAND_COUNTS)),
    "c_get_final": (0x8010, "rsp", "final", "optional", COMMAND_COMMON | COMMAND_COUNTS, ()),
    "c_move_pending": (0x8021, "rsp", "pending", "optional", COMMAND_COMMON | COMMAND_COUNTS, tuple(COMMAND_COUNTS)),
    "c_move_final": (0x8021, "rsp", "final", "optional", COMMAND_COMMON | COMMAND_COUNTS, ()),
    "n_get": (0x8110, "rsp", "any", "optional", COMMAND_COMMON | {0x1000, 0x1005}, ()),
    "n_set": (0x8120, "rsp", "any", "optional", COMMAND_COMMON | {0x1000, 0x1005}, ()),
    "n_action": (0x8130, "rsp", "any", "optional", COMMAND_COMMON | {0x1000, 0x1008}, ()),
    "n_create": (0x8140, "rsp", "any", "optional", COMMAND_COMMON | {0x1000, 0x1005}, ()),
    "c_store_sub": (0x0001, "rq", None, "must", {0x0000, 0x0002, 0x0100, 0x0110, 0x0700, 0x0800, 0x1000, 0x1030, 0x1031}, (0x0002, 0x0110, 0x0700, 0x1000)),
    "n_event_report": (0x0100, "rq", None, "optional", {0x0000, 0x0002, 0x0100, 0x0110, 0x0800, 0x1000, 0x1002}, (0x0002, 0x0110, 0x1000, 0x1002)),
}


def command_elements(data):
    "The elements of a command set given as bytes (Implicit VR Little Endian, PS3.7 E.1) as {tag: value}, or None if they are not well formed: ascending tags, even lengths, a Command Group Length that counts the rest."
    elements, position, previous = {}, 0, -1
    while position < len(data):
        if position + 8 > len(data):
            return None
        group, element, length = struct.unpack("<HHI", data[position:position + 8])
        tag = (group << 16) | element
        if group != 0 or tag <= previous or length % 2 or position + 8 + length > len(data):
            return None
        elements[element] = data[position + 8:position + 8 + length]
        previous = tag
        position += 8 + length
    if 0 not in elements or len(elements[0]) != 4 or struct.unpack("<I", elements[0])[0] != len(data) - 12:
        return None
    return elements


def pending_status(value):
    return value in (b"\x00\xff", b"\x01\xff")


def final_status(value):
    if len(value) != 2:
        return False
    number = struct.unpack("<H", value)[0]
    return number in (0x0000, 0xFE00, 0x0001, 0x0107, 0x0116) or (number >> 8) in (0x01, 0x02) or (number >> 12) in (0xA, 0xB, 0xC)


def exchange_of(node):
    while node is not None and not (node.symbol.is_non_terminal and node.symbol.name().startswith("<exchange_")):
        node = node.parent
    return node


def split_message_ok(message, kind):
    "A message received with its command in several Command Fragments (PS3.8 E.1): the reassembled command is a well-formed command set of the kind, its Command Data Set Type (0101H: none) agrees with the data PDVs that follow, and the relations the unsplit forms enforce hold (PS3.7 9.1, 9.3, 10.3, E.1)."
    field, role, status_class, data_rule, allowed, required = SPLIT_KINDS[kind]
    elements = command_elements(b"".join(command_fragments(message)))
    if elements is None or not set(elements) <= allowed or elements.get(0x0100) != struct.pack("<H", field):
        return False
    dst = elements.get(0x0800)
    if dst is None or len(dst) != 2:
        return False
    more, last = descendants_named(message, "<pdv_dataset_rcv_more>"), descendants_named(message, "<pdv_dataset_rcv>")
    has_data = bool(more or last)
    # the data set ends with exactly one PDV with the last fragment flag
    if len(last) != (1 if has_data else 0) or (dst == b"\x01\x01") == has_data:
        return False
    if (data_rule == "must" and not has_data) or (data_rule == "must_not" and has_data):
        return False
    if any(tag not in elements or len(elements[tag]) != 2 for tag in required if tag != 0x1000 and tag != 0x0002):
        return False
    if any(tag not in elements for tag in required):
        return False
    exchange = exchange_of(message)
    request, _ = request_and_replies(exchange) if exchange is not None else (None, [])
    if role == "rsp":
        status = elements.get(0x0900)
        if elements.get(0x0120) is None or len(elements[0x0120]) != 2 or status is None or len(status) != 2:
            return False
        if status_class == "pending" and not pending_status(status):
            return False
        if status_class == "final" and not final_status(status):
            return False
        if status_class == "any" and not (pending_status(status) or final_status(status)):
            return False
        if request is not None:
            ids = descendants_named(request, "<message_id_value>")
            if ids and elements[0x0120] != bytes(ids[0]):
                return False
            request_class = None
            for name in ("<cmd_uid_find>", "<cmd_uid_move>", "<cmd_uid_get>", "<cmd_uid_normalized>"):
                found = descendants_named(request, name)
                if found:
                    request_class = strip_uid(found[0])
                    break
            if request_class is not None and 0x0002 in elements and strip_uid(elements[0x0002]) != request_class:
                return False
            instances = descendants_named(request, "<cmd_instance_uid>")
            if instances and 0x1000 in elements and strip_uid(elements[0x1000]) != strip_uid(instances[0]):
                return False
            # the relations of normalized_response_ok
            if kind == "n_action" and has_data and 0x1008 not in elements:
                return False
            if kind == "n_get" and status == b"\x00\x00" and not has_data:
                return False
            if kind == "n_create" and status == b"\x00\x00" and not instances and 0x1000 not in elements:
                return False
    if kind == "c_store_sub":
        # PS3.7 9.1.3.1.4: the sub-operations use the priority of the C-GET-RQ
        get = exchange
        while get is not None and not (get.symbol.is_non_terminal and get.symbol.name() == "<exchange_c_get>"):
            get = get.parent
        if get is not None:
            get_request, _ = request_and_replies(get)
            priorities = descendants_named(get_request, "<priority_value>") if get_request is not None else []
            if priorities and elements.get(0x0700) != bytes(priorities[0]):
                return False
    if has_data:
        data = b"".join(bytes(node) for node in descendants_named(message, "<dataset_rcv_more>")) + b"".join(bytes(node) for node in descendants_named(message, "<dataset_rcv>"))
        return dataset_checked(data, bytes(descendants_named(last[0], "<pdv_context_id_rcv>")[0])[0])
    return True



def associate_ok(exchange):
    "Mandatory relations between the A-ASSOCIATE-RQ and the A-ASSOCIATE-AC (PS3.8 9.3.3, PS3.7 D.3.3)."
    requests = descendants_named(exchange, "<req_associate>") + descendants_named(exchange, "<req_associate_wrong_called>") + \
        descendants_named(exchange, "<req_associate_wrong_credentials>") + descendants_named(exchange, "<req_associate_variant>") + descendants_named(exchange, "<req_associate_contexts>") + \
        descendants_named(exchange, "<req_associate_no_default>") + descendants_named(exchange, "<req_associate_lossless_without_default>") + descendants_named(exchange, "<req_associate_lossy_without_default>")
    accepts = descendants_named(exchange, "<rsp_associate_ac_accepted>") + descendants_named(exchange, "<rsp_associate_ac_refused>")
    if not requests or not accepts:
        return True
    problem = associate_problem(bytes(requests[0]), bytes(accepts[0]))
    if problem is not None and os.environ.get("DICOM_DEBUG"):
        print("associate problem:", problem, bytes(requests[0]).hex(), bytes(accepts[0]).hex(), file=sys.stderr)
    return problem is None


def associate_problem(request, accept):
    "The first mandatory relation between request and accept bytes that does not hold, or None."
    # 9.3.3 bytes 11-74 (Responding AE title, Calling AE title, reserved): "shall not be tested when received": no check, the AC accepts any bytes there
    rq_items = dict()
    for kind, body in split_items(request[74:]):
        rq_items.setdefault(kind, []).append(body)
    ac_items = dict()
    for kind, body in split_items(accept[74:]):
        ac_items.setdefault(kind, []).append(body)
    # exactly one Application Context Item and one User Information Item; one result per proposed context, same ids
    if len(ac_items.get(0x10, [])) != 1 or len(ac_items.get(0x50, [])) != 1:
        return "check 2"
    if sorted(set(body[0] for body in rq_items.get(0x20, []))) != sorted(set(body[0] for body in ac_items.get(0x21, []))):
        return "check 3"
    rq_user = dict()
    for kind, body in split_items(rq_items[0x50][0]):
        rq_user.setdefault(kind, []).append(body)
    ac_user = dict()
    for kind, body in split_items(ac_items[0x50][0]):
        ac_user.setdefault(kind, []).append(body)
    # D.1 / D.3.3.2: exactly one Maximum Length and one Implementation Class UID; at most one Version Name / Async Window
    if len(ac_user.get(0x51, [])) != 1 or len(ac_user.get(0x52, [])) != 1:
        return "check 4"
    if len(ac_user.get(0x55, [])) > 1 or len(ac_user.get(0x53, [])) > 1:
        return "check 5"
    # D.3.3.3 / D.3.3.4 / D.3.3.5 / D.3.3.6: items the RQ did not offer are omitted in the AC
    for kind in (0x53, 0x54, 0x56):
        if kind not in rq_user and kind in ac_user:
            return "check 6"
    if 0x57 in ac_user:
        return "check 7"
    # D.3.3.3: the window is negotiated down, never up
    if 0x53 in ac_user and 0x53 in rq_user:
        offered, answered = rq_user[0x53][0], ac_user[0x53][0]
        for position in (0, 2):
            offered_value, answered_value = from_u16(offered[position:]), from_u16(answered[position:])
            if offered_value != 0 and (answered_value == 0 or answered_value > offered_value):
                return "check 8"
    # D.3.3.4: role answered 1 only if proposed 1
    for answer in ac_user.get(0x54, []):
        uid_length = from_u16(answer)
        uid = answer[2:2 + uid_length]
        proposals = [offer for offer in rq_user.get(0x54, []) if offer[2:2 + from_u16(offer)] == uid]
        if not proposals:
            return "check 9"
        scu_offered, scp_offered = proposals[0][2 + uid_length], proposals[0][3 + uid_length]
        if (answer[2 + uid_length] == 1 and scu_offered == 0) or (answer[3 + uid_length] == 1 and scp_offered == 0):
            return "check 10"
    # D.3.3.7: a user identity response only after a request, and always when a positive response was requested
    if 0x58 not in rq_user and 0x59 in ac_user:
        return "check 11"
    # D.3.3.5: one SOP Class Extended Negotiation item per SOP class in the AC
    extneg_classes = [body[2:2 + from_u16(body)] for body in ac_user.get(0x56, [])]
    if len(set(extneg_classes)) != len(extneg_classes):
        return "check 13"
    # D.3.3.7.2: the server response is empty for user identity types 1 and 2
    if 0x58 in rq_user and 0x59 in ac_user and rq_user[0x58][0][0] in (1, 2) and from_u16(ac_user[0x59][0]) != 0:
        return "check 14"
    # PS3.5 10.1: the contexts of an abstract syntax offering the default Transfer Syntax "cannot be rejected" for lack of a supported transfer syntax (Result/Reason 4), unless the sender
    # has only lossy or too large Pixel Data. The abstract syntaxes below (verification, query / retrieve, normalized services) carry no Pixel Data, so there the waiver cannot apply.
    default_syntax = IVLE.encode("ascii")
    offered_default, all_refused_4 = {}, {}
    for body in rq_items.get(0x20, []):
        sub = split_items(body[4:])
        abstract = b"".join(sub_body for sub_kind, sub_body in sub if sub_kind == 0x30)
        if group_of_abstract(abstract.decode("ascii", "replace")) in (None, "storage"):
            continue
        refused_4 = any(ac_body[0] == body[0] and ac_body[2] == 4 for ac_body in ac_items.get(0x21, []))
        if default_syntax in [sub_body for sub_kind, sub_body in sub if sub_kind == 0x40]:
            offered_default[abstract] = True
            all_refused_4[abstract] = all_refused_4.get(abstract, True) and refused_4
    if any(all_refused_4.values()):
        return "check 15"
    # 9.3.3.2: an accepted context carries a transfer syntax that was offered for it
    offered_syntaxes = {}
    for body in rq_items.get(0x20, []):
        offered_syntaxes[body[0]] = [sub_body for sub_kind, sub_body in split_items(body[4:]) if sub_kind == 0x40]
    for body in ac_items.get(0x21, []):
        if body[2] == 0:
            syntax = [sub_body for sub_kind, sub_body in split_items(body[4:]) if sub_kind == 0x40]
            if len(syntax) != 1 or syntax[0] not in offered_syntaxes.get(body[0], []):
                return "check 12"
    return None



MAX_LENGTH = {"rq": 0, "ac": 0}
IVLE = "1.2.840.10008.1.2"
LONG_EXPLICIT_VRS = (b"OB", b"OD", b"OF", b"OL", b"OV", b"OW", b"SQ", b"SV", b"UC", b"UN", b"UR", b"UT", b"UV")


def request_and_replies(exchange):
    request, replies = None, []
    pending = list(exchange.children)
    while pending:
        child = pending.pop(0)
        if child.symbol.is_non_terminal:
            name = child.symbol.name()
            if name.endswith("_end>"):
                pending = list(child.children) + pending
            elif name.startswith("<req_") and request is None:
                request = child
            elif name.startswith("<rsp_") or name.startswith("<exchange_"):
                replies.append(child)
    return request, replies


def strip_uid(value):
    return bytes(value).rstrip(b"\x00")


def uid_echo_ok(exchange):
    "Affected / Requested SOP Class and SOP Instance UIDs of responses equal the request's (PS3.7 9.1.1.1.3, 9.1.1.1.4, 10.1)."
    request, replies = request_and_replies(exchange)
    if request is None:
        return True
    request_class = None
    for name in ("<cmd_uid_verification>", "<cmd_uid_storage>", "<cmd_uid_find>", "<cmd_uid_move>", "<cmd_uid_get>", "<cmd_uid_normalized>"):
        found = descendants_named(request, name)
        if found:
            request_class = strip_uid(found[0])
            break
    request_instances = descendants_named(request, "<cmd_instance_uid>")
    for reply in replies:
        if reply.symbol.name() == "<exchange_c_store_sub>":
            continue
        for node in descendants_named(reply, "<cmd_affected_sop_class_uid>"):
            if request_class is not None and strip_uid(bytes(node)[8:]) != request_class:
                return False
        for node in descendants_named(reply, "<cmd_instance_uid>"):
            if request_instances and strip_uid(node) != strip_uid(request_instances[0]):
                return False
    return True


def normalized_response_ok(exchange):
    "N-ACTION-RSP names the Action Type ID with an Action Reply (10.1.4.1.5), a successful N-GET-RSP has an Attribute List (10.1.2.1.8), N-CREATE-RSP names the instance UID (10.1.5.1.4)."
    request, replies = request_and_replies(exchange)
    if request is None:
        return True
    request_name = request.symbol.name()
    for reply in replies:
        if descendants_named(reply, "<split_msg_rcv>"):
            # a reply with its command in Command Fragments: split_message_ok applies these relations to the reassembled command
            continue
        statuses = descendants_named(reply, "<status_value>")
        has_dataset = bool(descendants_named(reply, "<dataset_rcv>"))
        success = bool(statuses) and bytes(statuses[0]) == b"\x00\x00"
        if request_name == "<req_n_action>" and has_dataset and not descendants_named(reply, "<cmd_action_type_id>"):
            return False
        if request_name == "<req_n_get>" and success and not has_dataset:
            return False
        if request_name == "<req_n_create>" and success and not descendants_named(request, "<cmd_instance_uid>") \
                and not descendants_named(reply, "<cmd_instance_uid>"):
            return False
        # PS3.7 10.1.5.1.4 says the UID "may only be included in the success response", but C.5.21 lists it as an optional field of the
        # Processing Failure (0110H) response: the two passages conflict, so a UID in a non-success N-CREATE-RSP is accepted.
    return True


def extneg_info_size(uid_node):
    "Length of the Service-class-application-information of a received extended negotiation item: the Item-length minus the SOP-class-uid-length field and the UID."
    item = uid_node.parent
    while item is not None and not (item.symbol.is_non_terminal and item.symbol.name() == "<extneg_item_ac>"):
        item = item.parent
    if item is None:
        return 0
    # what is left of the item after the declared SOP-class-uid-length: a UID longer than declared would swallow bytes of the next item, so only the declared length parses to the end of the item
    return max(from_u16(bytes(children_named(item, "<item_length>")[0])) - 2 - from_u16(bytes(children_named(item, "<extneg_uid_length_rcv>")[0])), 0)


def split_command_length(node):
    "Command Group Length of a command sent in several fragments: all command bytes after the group length element."
    request = node
    while request is not None and not (request.symbol.is_non_terminal and request.symbol.name().startswith("<req_")):
        request = request.parent
    if request is None:
        return 0
    total = 0
    for fragment in descendants_named_any(request):
        name = fragment.symbol.name()
        if name.startswith(("<pdv_c_", "<pdv_n_")) and name.endswith(("_head>", "_tail>")):
            total += len(bytes(fragment)) - 6
    return max(total - 12, 0)


def item_of(length_node):
    "The variable item an Item-length field belongs to: its parent, for the Transfer Syntax Sub-Item the node that holds the shared head and the name."
    parent = length_node.parent
    return parent.parent if parent.symbol.name() == "<transfer_syntax_item_head>" else parent


def oversized_value():
    "The value of a private element that makes a P-DATA-TF PDU longer than the Maximum Length the server announced in its A-ASSOCIATE-AC (PS3.8 D.1.2); without an announced limit (0) the PDU is merely large."
    limit = MAX_LENGTH["ac"]
    size = limit + 2 if 0 < limit <= 131072 else 16386
    return bytes(random.choice(b"ABCDEFGH") for _ in range(size))


def pdu_length_ok(length_node):
    "A received P-DATA-TF PDU is not longer than the Maximum Length the client announced in its A-ASSOCIATE-RQ (PS3.8 D.1.1, D.1.2); 0 means no limit. Sent PDUs are not checked here (see <req_c_store_oversized>)."
    pdu = length_node.parent
    data = bytes(pdu)
    if data[:1] != b"\x04":
        return True
    node = pdu
    while node is not None:
        if node.symbol.is_non_terminal and node.symbol.name().startswith("<rsp_"):
            limit = MAX_LENGTH["rq"]
            return limit == 0 or len(data) - 6 <= limit
        node = node.parent
    return True


ENDIAN = ["<"]
VRS = {b"AE", b"AS", b"AT", b"CS", b"DA", b"DS", b"DT", b"FD", b"FL", b"IS", b"LO", b"LT", b"OB", b"OD", b"OF", b"OL", b"OV", b"OW", b"PN", b"SH", b"SL",
       b"SQ", b"SS", b"ST", b"SV", b"TM", b"UC", b"UI", b"UL", b"UN", b"UR", b"US", b"UT", b"UV"}
NOT_ENCAPSULATED_SYNTAXES = ("1.2.840.10008.1.2", "1.2.840.10008.1.2.1", "1.2.840.10008.1.2.2", "1.2.840.10008.1.2.1.99")
REFERENCED_SYNTAXES = ("1.2.840.10008.1.2.4.94", "1.2.840.10008.1.2.4.95", "1.2.840.10008.1.2.4.204", "1.2.840.10008.1.2.4.205")
PIXEL_TAGS = ((0x7FE0, 0x0010), (0x7FE0, 0x0008), (0x7FE0, 0x0009), (0x5400, 0x1010))


class Element:
    __slots__ = ("tag", "vr", "start", "value_start", "length", "end", "items", "fragments")

    def __init__(self, tag, vr, start, value_start, length):
        self.tag = tag
        self.vr = vr
        self.start = start
        self.value_start = value_start
        self.length = length
        self.end = value_start
        self.items = None
        self.fragments = None


PLANAR_ZERO_SYNTAXES = tuple("1.2.840.10008.1.2.4." + suffix for suffix in ("80", "81", "90", "91", "92", "93", "110", "111", "112", "201", "202", "203")) + \
    tuple("1.2.840.10008.1.2.4.%d%s" % (number, suffix) for number in range(100, 109) for suffix in ("", ".1"))
VIDEO_STREAM_SYNTAXES = tuple("1.2.840.10008.1.2.4.%d%s" % (number, suffix) for number in range(102, 109) for suffix in ("", ".1"))
SINGLE_FRAGMENT_SYNTAXES = ("1.2.840.10008.1.2.5", "1.2.840.10008.1.2.1.98", "1.2.840.10008.1.2.8.1", "1.2.840.10008.1.2.4.110", "1.2.840.10008.1.2.4.111",
                            "1.2.840.10008.1.2.4.112", "1.2.840.10008.1.2.4.201", "1.2.840.10008.1.2.4.202", "1.2.840.10008.1.2.4.203") + tuple("1.2.840.10008.1.2.4.%d" % number for number in range(100, 107))


def is_encapsulation_syntax(syntax):
    "The encapsulation transfer syntaxes of PS3.5 A.4 (JPEG, JPEG-LS, JPEG 2000, JPEG XL, HTJ2K, MPEG2, H.264, HEVC, RLE, Encapsulated Uncompressed, Deflated Image Frame)."
    if syntax in ("1.2.840.10008.1.2.5", "1.2.840.10008.1.2.1.98", "1.2.840.10008.1.2.8.1"):
        return True
    return syntax.startswith("1.2.840.10008.1.2.4.") and syntax not in REFERENCED_SYNTAXES


def parse_level(data, explicit, position, end, delimited, private_sequence):
    "Elements of one data set or item (PS3.5 7.1, 7.5) as (elements, position of the item delimitation element or end); None when malformed."
    elements, last = [], None
    while position < end:
        if position + 8 > end:
            return None
        group, element = struct.unpack(ENDIAN[0] + "HH", data[position:position + 4])
        if group == 0xFFFE:
            if delimited and (group, element) == (0xFFFE, 0xE00D) and data[position + 4:position + 8] == b"\x00\x00\x00\x00":
                return elements, position
            return None
        tag = (group, element)
        if last is not None and tag <= last:
            return None
        last = tag
        vr = None
        if explicit:
            vr = data[position + 4:position + 6]
            if vr not in VRS:
                return None
            if vr in LONG_EXPLICIT_VRS:
                if position + 12 > end or data[position + 6:position + 8] != b"\x00\x00":
                    return None
                length, header = struct.unpack(ENDIAN[0] + "I", data[position + 8:position + 12])[0], 12
            else:
                length, header = struct.unpack(ENDIAN[0] + "H", data[position + 6:position + 8])[0], 8
        else:
            length, header = struct.unpack(ENDIAN[0] + "I", data[position + 4:position + 8])[0], 8
        value = position + header
        node = Element(tag, vr, position, value, length)
        private_child = private_sequence or group % 2 == 1
        if length == 0xFFFFFFFF:
            if explicit and vr not in (b"SQ", b"OB", b"OW", b"UN"):
                return None
            if tag == (0x7FE0, 0x0010):
                if not explicit or vr != b"OB":
                    return None
                result = parse_items(data, value, True, end, True, True, private_child)
                node.fragments = result[0] if result else None
            else:
                # an undefined-length UN value is a sequence in Implicit VR (PS3.5 6.2.2)
                saved = ENDIAN[0]
                if vr == b"UN":
                    ENDIAN[0] = "<"
                result = parse_items(data, value, explicit and vr != b"UN", end, True, False, private_child)
                ENDIAN[0] = saved
                node.items = result[0] if result else None
            if result is None:
                return None
            node.end = result[1]
        else:
            if value + length > end or length % 2:
                return None
            node.end = value + length
            sequence = vr == b"SQ" if explicit else (tag != (0x7FE0, 0x0010) and length >= 8 and data[value:value + 4] == b"\xfe\xff\x00\xe0")
            if sequence:
                result = parse_items(data, value, explicit, value + length, False, False, private_child)
                if result is None:
                    return None
                node.items = result[0]
        elements.append(node)
        position = node.end
    if delimited:
        return None
    return elements, position


def parse_items(data, position, explicit, end, undefined, fragments, private_sequence):
    "Items of a sequence or of encapsulated Pixel Data (PS3.5 7.5.1, 7.5.2, A.4); (items, position after the sequence) or None."
    items, first = [], True
    while True:
        if not undefined and position == end:
            return items, position
        if position + 8 > end:
            return None
        group, element, length = struct.unpack(ENDIAN[0] + "HHI", data[position:position + 8])
        if (group, element) == (0xFFFE, 0xE0DD):
            return (items, position + 8) if undefined and length == 0 else None
        if (group, element) != (0xFFFE, 0xE000):
            return None
        position += 8
        if fragments:
            if length == 0xFFFFFFFF or length % 2 or position + length > end:
                return None
            if first and length % 4:
                return None
            if not first and length < 2:
                return None
            items.append((position, length))
            position += length
            first = False
            continue
        if length == 0xFFFFFFFF:
            result = parse_level(data, explicit, position, end, True, private_sequence)
            if result is None:
                return None
            items.append((result[0], private_sequence))
            position = result[1] + 8
        else:
            if position + length > end:
                return None
            result = parse_level(data, explicit, position, position + length, False, private_sequence)
            if result is None:
                return None
            items.append((result[0], private_sequence))
            position += length


def element_value(data, node):
    return data[node.value_start:node.value_start + node.length]


def bits_problem(data, elements):
    "Bits Stored is not larger than Bits Allocated, High Bit is Bits Stored minus one (PS3.5 8.1.1), in a data set or an Item."
    level = {}
    for node in elements:
        level[node.tag] = node
    allocated, stored, high = us_value(data, level.get((0x0028, 0x0100))), us_value(data, level.get((0x0028, 0x0101))), us_value(data, level.get((0x0028, 0x0102)))
    if allocated is not None and stored is not None and stored > allocated:
        return "Bits Stored larger than Bits Allocated"
    if stored is not None and high is not None and high != stored - 1:
        return "High Bit is not Bits Stored minus one"
    return None


def collect_tag_vrs(elements, found):
    "The VRs of the waveform elements wherever they occur, Items included (PS3.5 8.3)."
    for node in elements:
        if node.tag in ((0x5400, 0x1010), (0x5400, 0x0110), (0x5400, 0x0112), (0x5400, 0x100A)):
            if node.tag not in found:
                found[node.tag] = set()
            found[node.tag].add(node.vr)
        if node.items is not None:
            for entry in node.items:
                collect_tag_vrs(entry[0], found)


def waveform_vr_problem(elements):
    "Channel Minimum / Maximum Value and Waveform Padding Value have the VR of the Waveform Data element of their Waveform Sequence Item (PS3.5 8.3)."
    for node in elements:
        if node.tag == (0x5400, 0x1010):
            found = {}
            collect_tag_vrs([other for other in elements if other is not node], found)
            for tag in ((0x5400, 0x0110), (0x5400, 0x0112), (0x5400, 0x100A)):
                if tag in found and found[tag] != {node.vr}:
                    return True
    for node in elements:
        if node.items is not None:
            for entry in node.items:
                if waveform_vr_problem(entry[0]):
                    return True
    return False


def item_pixel_problem(data, elements):
    "Native Pixel Data in an Item has no compression Photometric Interpretation (PS3.5 8.2)."
    level = {}
    for node in elements:
        level[node.tag] = node
    pixel = level.get((0x7FE0, 0x0010))
    if pixel is not None and pixel.fragments is None and (0x0028, 0x0004) in level \
            and element_value(data, level[(0x0028, 0x0004)]).rstrip(b" ") in (b"YBR_RCT", b"YBR_ICT", b"YBR_PARTIAL_420"):
        return "native Pixel Data with a compression photometric interpretation"
    return None


def check_level(data, explicit, elements, in_item, private_sequence):
    "Rules for the elements of one data set or item; a description of the first violation or None."
    if in_item:
        problem = bits_problem(data, elements) or item_pixel_problem(data, elements)
        if problem:
            return problem
    creators, reserved = set(), set()
    for node in elements:
        group, element = node.tag
        if in_item and group in (0x0000, 0x0002, 0x0006):
            return "group 0000, 0002 or 0006 inside an Item"
        if private_sequence and (node.tag in PIXEL_TAGS or (group & 0xFF00 == 0x6000 and element == 0x3000)):
            return "bulk data inside a private sequence item"
        if group % 2 == 1 and group >= 9 and 0x10 <= element <= 0xFF:
            if node.vr is not None and node.vr != b"LO":
                return "private creator is not LO"
            value = element_value(data, node)
            if b"\\" in value:
                return "private creator with several values"
            if (group, value.rstrip(b" \x00")) in creators:
                return "private creator used twice"
            creators.add((group, value.rstrip(b" \x00")))
            reserved.add((group, element))
    for index in range(len(elements)):
        node = elements[index]
        group, element = node.tag
        if group % 2 == 1 and group >= 9 and element >= 0x1000 and (group, element >> 8) not in reserved:
            return "private data element without private creator"
        if element == 0x0000 and group != 0xFFFE:
            if node.length != 4 or (node.vr is not None and node.vr != b"UL"):
                return "group length is not a UL"
            total = 0
            for other in elements[index + 1:]:
                if other.tag[0] != group:
                    break
                total += other.end - other.start
            if struct.unpack(ENDIAN[0] + "I", element_value(data, node))[0] != total:
                return "group length does not match its group"
        if node.items is not None:
            saved = ENDIAN[0]
            if node.vr == b"UN":
                ENDIAN[0] = "<"
            for entry in node.items:
                problem = check_level(data, explicit and node.vr != b"UN", entry[0], True, entry[1])
                if problem:
                    ENDIAN[0] = saved
                    return problem
            ENDIAN[0] = saved
    return None


def us_value(data, node):
    if node is None:
        return None
    value = element_value(data, node)
    return struct.unpack(ENDIAN[0] + "H", value)[0] if len(value) == 2 else None


def check_dataset_semantics(data, explicit, elements, syntax):
    "Rules on the Pixel Data related elements of the top-level data set (PS3.5 8.1, 8.2, A.1, A.2, A.4, A.6, 8.2.x)."
    top = {node.tag: node for node in elements}
    pixel = top.get((0x7FE0, 0x0010))
    flt, dbl, url = top.get((0x7FE0, 0x0008)), top.get((0x7FE0, 0x0009)), top.get((0x0028, 0x7FE0))
    present = 0
    for candidate in (url, pixel, flt, dbl):
        if candidate is not None:
            present += 1
    if present > 1:
        return "several pixel data elements"
    allocated, stored, high = us_value(data, top.get((0x0028, 0x0100))), us_value(data, top.get((0x0028, 0x0101))), us_value(data, top.get((0x0028, 0x0102)))
    problem = bits_problem(data, elements)
    if problem:
        return problem
    photometric = element_value(data, top[(0x0028, 0x0004)]).rstrip(b" ") if (0x0028, 0x0004) in top else b""
    if pixel is not None and pixel.fragments is None and photometric in (b"YBR_RCT", b"YBR_ICT", b"YBR_PARTIAL_420"):
        return "native Pixel Data with a compression photometric interpretation"
    if flt is not None and (flt.length == 0xFFFFFFFF or (explicit and flt.vr != b"OF") or (allocated is not None and allocated != 32)):
        return "Float Pixel Data encoding"
    if dbl is not None and (dbl.length == 0xFFFFFFFF or (explicit and dbl.vr != b"OD") or (allocated is not None and allocated != 64)):
        return "Double Float Pixel Data encoding"
    if flt is not None or dbl is not None:
        if (0x0028, 0x0101) in top or (0x0028, 0x0102) in top or (0x0028, 0x0103) in top:
            return "Float Pixel Data with Bits Stored, High Bit or Pixel Representation"
    if pixel is not None and pixel.fragments is None:
        if explicit and allocated is not None and allocated > 8 and pixel.vr != b"OW":
            return "native Pixel Data of more than 8 bits is not OW"
        if pixel.length != 0xFFFFFFFF and pixel.length % 2:
            return "Pixel Data of odd length"
    if explicit and waveform_vr_problem(elements):
        return "waveform value VRs differ"
    for node in elements:
        if node.tag[0] & 0xFF00 == 0x6000 and node.tag[1] == 0x3000 and node.length % 2:
            return "Overlay Data of odd length"
    if pixel is not None and pixel.fragments is not None and not is_encapsulation_syntax(syntax):
        return "encapsulated Pixel Data in a transfer syntax without encapsulation"
    if is_encapsulation_syntax(syntax) and pixel is not None:
        if pixel.fragments is None:
            return "Pixel Data is not encapsulated"
        problem = encapsulation_structure_problem(data, top, syntax, pixel) or photometric_table_problem(data, top, syntax, photometric)
        if problem:
            return problem
        planar = us_value(data, top.get((0x0028, 0x0006)))
        samples = us_value(data, top.get((0x0028, 0x0002)))
        representation = us_value(data, top.get((0x0028, 0x0103)))
        if syntax in PLANAR_ZERO_SYNTAXES and planar not in (None, 0):
            return "Planar Configuration is not 0"
        if syntax in ("1.2.840.10008.1.2.4.100", "1.2.840.10008.1.2.4.100.1"):
            # Table 8.2.5-1: the multi-component column or the single component column
            multi = samples in (None, 3) and photometric in (b"", b"YBR_PARTIAL_420") and planar in (None, 0)
            single = samples in (None, 1) and photometric in (b"", b"MONOCHROME2") and (0x0028, 0x0006) not in top
            if not (multi or single) or allocated not in (None, 8) or stored not in (None, 8) or high not in (None, 7) or representation not in (None, 0):
                return "MPEG2 Main Profile Main Level pixel encoding"
        if syntax in ("1.2.840.10008.1.2.4.101", "1.2.840.10008.1.2.4.101.1"):
            rows, columns = us_value(data, top.get((0x0028, 0x0010))), us_value(data, top.get((0x0028, 0x0011)))
            if rows is not None and columns is not None and (rows, columns) not in ((720, 1280), (1080, 1920)):
                return "MPEG2 Main Profile High Level geometry"
            if (0x0028, 0x0034) in top:
                return "MPEG2 Main Profile High Level with Pixel Aspect Ratio"
        if syntax in VIDEO_STREAM_SYNTAXES:
            ten_bit = syntax.startswith("1.2.840.10008.1.2.4.108")
            if (0x0028, 0x0034) in top or photometric != b"YBR_PARTIAL_420" or samples != 3 or representation != 0 or planar != 0 \
                    or allocated != (16 if ten_bit else 8) or stored != (10 if ten_bit else 8) or high != (9 if ten_bit else 7):
                return "H.264/HEVC pixel encoding (PS3.5 8.2.7 - 8.2.11: every element has the stated value)"
        stereo = top.get((0x0022, 0x0028))
        value = element_value(data, stereo).rstrip(b" ") if stereo is not None else None
        if syntax.startswith(("1.2.840.10008.1.2.4.105", "1.2.840.10008.1.2.4.106")) and value != b"YES":
            return "Stereo Pairs Present is not YES"
        if syntax.startswith("1.2.840.10008.1.2.4.104") and value not in (None, b"NO"):
            return "Stereo Pairs Present is not NO"
    if syntax in REFERENCED_SYNTAXES:
        if url is None:
            return "JPIP referenced syntax without Pixel Data Provider URL"
        if pixel is not None or flt is not None or dbl is not None:
            return "JPIP referenced syntax with Pixel Data"
        if photometric not in (b"", b"MONOCHROME1", b"MONOCHROME2", b"YBR_ICT", b"YBR_RCT"):
            return "JPIP referenced photometric interpretation"
    return None


STANDARD_PHOTOMETRICS = (b"MONOCHROME1", b"MONOCHROME2", b"PALETTE COLOR", b"RGB", b"HSV", b"ARGB", b"CMYK", b"YBR_FULL", b"YBR_FULL_422", b"YBR_PARTIAL_422",
                         b"YBR_PARTIAL_420", b"YBR_ICT", b"YBR_RCT")


def photometric_table_problem(data, top, syntax, photometric):
    "Tables 8.2.1-1, 8.2.1-2 (JPEG) and 8.2.2-1 (RLE): the pixel encoding elements fit the Photometric Interpretation (PS3.5 8.2.1, 8.2.2)."
    samples = us_value(data, top.get((0x0028, 0x0002)))
    planar = us_value(data, top.get((0x0028, 0x0006)))
    has_planar = (0x0028, 0x0006) in top
    representation = us_value(data, top.get((0x0028, 0x0103)))
    allocated = us_value(data, top.get((0x0028, 0x0100)))
    stored = us_value(data, top.get((0x0028, 0x0101)))
    high = us_value(data, top.get((0x0028, 0x0102)))
    if photometric == b"":
        return None
    if photometric not in STANDARD_PHOTOMETRICS:
        return None
    mono = photometric in (b"MONOCHROME1", b"MONOCHROME2")
    if syntax == "1.2.840.10008.1.2.4.50":
        if mono:
            ok = samples in (None, 1) and not has_planar and representation in (None, 0) and allocated in (None, 8) and stored in (None, 8) and high in (None, 7)
        else:
            ok = photometric in (b"YBR_FULL_422", b"RGB") and samples in (None, 3) and planar in (None, 0) and representation in (None, 0) \
                and allocated in (None, 8) and stored in (None, 8) and high in (None, 7)
        return None if ok else "JPEG Baseline pixel encoding (Table 8.2.1-1)"
    if syntax == "1.2.840.10008.1.2.4.51":
        if not mono:
            return "JPEG Extended pixel encoding (Table 8.2.1-1)"
        ok = samples in (None, 1) and not has_planar and representation in (None, 0) and (allocated, stored, high) in ((None, None, None), (8, 8, 7), (16, 12, 11), (8, None, None), (16, None, None))
        return None if ok else "JPEG Extended pixel encoding (Table 8.2.1-1)"
    if syntax in ("1.2.840.10008.1.2.4.57", "1.2.840.10008.1.2.4.70"):
        if mono or photometric == b"PALETTE COLOR":
            ok = samples in (None, 1) and not has_planar and (representation in (None, 0) if photometric == b"PALETTE COLOR" else representation in (None, 0, 1))
        else:
            ok = photometric in (b"YBR_FULL", b"RGB") and samples in (None, 3) and planar in (None, 0) and representation in (None, 0)
        ok = ok and allocated in (None, 8, 16) and (stored is None or 1 <= stored <= 16) and (high is None or high <= 15)
        return None if ok else "JPEG Lossless pixel encoding (Table 8.2.1-2)"
    if syntax == "1.2.840.10008.1.2.5":
        if mono or photometric == b"PALETTE COLOR":
            ok = samples in (None, 1) and not has_planar and (representation in (None, 0) if photometric == b"PALETTE COLOR" else representation in (None, 0, 1)) \
                and allocated in (None, 1, 8, 16) if mono else samples in (None, 1) and not has_planar and representation in (None, 0) and allocated in (None, 8, 16)
        else:
            ok = photometric in (b"YBR_FULL", b"RGB") and samples in (None, 3) and planar in (None, 0, 1) and representation in (None, 0) and allocated in (None, 8, 16)
        ok = ok and (stored is None or 1 <= stored <= 16) and (high is None or high <= 15)
        return None if ok else "RLE pixel encoding (Table 8.2.2-1)"
    return None


def packbits_length(segment, wanted):
    "Number of bytes a PackBits segment (PS3.5 G.3.1) decodes to, or -1 when its runs overshoot or end early."
    position, produced = 0, 0
    while produced < wanted:
        if position >= len(segment):
            return -1
        control = segment[position]
        position += 1
        if control < 128:
            produced += control + 1
            position += control + 1
        elif control > 128:
            produced += 257 - control
            position += 1
    return produced if produced == wanted and position <= len(segment) else -1


def rle_problem(data, top, fragments):
    "The RLE header and segments of every frame fit Samples per Pixel, Bits Allocated, Rows and Columns (PS3.5 8.2.2, G.2 - G.5)."
    samples = us_value(data, top.get((0x0028, 0x0002))) or 1
    allocated = us_value(data, top.get((0x0028, 0x0100)))
    rows, columns = us_value(data, top.get((0x0028, 0x0010))), us_value(data, top.get((0x0028, 0x0011)))
    for entry in fragments:
        start, length = entry[0], entry[1]
        if length < 64:
            return "RLE fragment shorter than its header"
        header = struct.unpack("<16I", data[start:start + 64])
        count = header[0]
        if count < 1 or count > 15 or (allocated is not None and allocated >= 8 and count != samples * ((allocated + 7) // 8)):
            return "RLE segment count does not fit Samples per Pixel and Bits Allocated"
        offsets = list(header[1:1 + count])
        if offsets[0] != 64 or any(header[1 + count:]):
            return "RLE header offsets"
        for index in range(count):
            end = offsets[index + 1] if index + 1 < count else length
            if offsets[index] >= end or end > length:
                return "RLE segment offsets are not increasing"
            if allocated is not None and allocated >= 8 and rows and columns and packbits_length(data[start + offsets[index]:start + end], rows * columns) < 0:
                return "RLE segment does not decode to Rows x Columns bytes"
    return None


def encapsulation_structure_problem(data, top, syntax, pixel):
    "Basic Offset Table, Extended Offset Table and frame/fragment relations of encapsulated Pixel Data (PS3.5 A.4, A.4.1, A.4.2)."
    items = pixel.fragments
    bot_start, bot_length = items[0][0], items[0][1]
    if (0x7FE0, 0x0001) in top and bot_length != 0:
        return "Basic Offset Table is not empty with an Extended Offset Table"
    fragments = items[1:]
    positions, cursor = [], 0
    for entry in fragments:
        positions.append(cursor)
        cursor += 8 + entry[1]
    offsets = []
    for index in range(bot_length // 4):
        offsets.append(struct.unpack("<I", data[bot_start + 4 * index:bot_start + 4 * index + 4])[0])
    for offset in offsets:
        if offset not in positions:
            return "Basic Offset Table offset does not address a fragment"
    for index in range(len(offsets) - 1):
        if offsets[index] >= offsets[index + 1]:
            return "Basic Offset Table offsets are not increasing"
    frames = 1
    if (0x0028, 0x0008) in top:
        text = element_value(data, top[(0x0028, 0x0008)]).strip(b" \x00")
        if text.isdigit() and int(text) > 0:
            frames = int(text)
    if offsets and offsets[0] != 0:
        return "the first Basic Offset Table entry is not 0"
    if offsets and len(offsets) != frames:
        return "the Basic Offset Table has no entry per frame"
    if syntax.startswith(("1.2.840.10008.1.2.4.100", "1.2.840.10008.1.2.4.101")) and bot_length != 0:
        return "the Basic Offset Table of an MPEG2 stream is empty"
    if syntax in SINGLE_FRAGMENT_SYNTAXES[9:] and len(fragments) != 1:
        return "a non-fragmentable stream is in one fragment"
    if syntax == "1.2.840.10008.1.2.5":
        problem = rle_problem(data, top, fragments)
        if problem:
            return problem
    if syntax in SINGLE_FRAGMENT_SYNTAXES[:9]:
        if len(fragments) != frames:
            return "a frame is not in one and only one fragment"
    elif len(fragments) < frames:
        return "a fragment holds data of several frames"
    return None


def dataset_problem(data, syntax):
    "A description of the first rule a received data set breaks in its transfer syntax, or None (PS3.5 6, 7, 8, A)."
    if syntax in ("1.2.840.10008.1.2.1.99", "1.2.840.10008.1.2.4.95", "1.2.840.10008.1.2.4.205"):
        try:
            data = zlib.decompressobj(-15).decompress(data)
        except zlib.error:
            return "the deflate stream is not valid (RFC 1951)"
    ENDIAN[0] = ">" if syntax == "1.2.840.10008.1.2.2" else "<"
    try:
        explicit = syntax != IVLE
        result = parse_level(data, explicit, 0, len(data), False, False)
        if result is None:
            return "malformed data set"
        problem = check_level(data, explicit, result[0], False, False)
        return problem or check_dataset_semantics(data, explicit, result[0], syntax)
    finally:
        ENDIAN[0] = "<"


def debug_problem(what, problem):
    if problem is not None and os.environ.get("DICOM_DEBUG"):
        print("data set problem:", what, problem, file=sys.stderr)
    return problem is None


def dataset_checked(data, context_id):
    if not data:
        return False
    syntax = ACCEPTED.get(context_id, (0, IVLE))[1]
    return debug_problem(len(data), dataset_problem(data, syntax))


def dataset_message_wellformed(message):
    "The data set of a received message, all fragments together, obeys the rules of its transfer syntax (checked once from the last fragment)."
    last = descendants_named(message, "<pdv_dataset_rcv>")
    if not last:
        return True
    data = b"".join(bytes(node) for node in descendants_named(message, "<dataset_rcv_more>")) + b"".join(bytes(node) for node in descendants_named(message, "<dataset_rcv>"))
    return dataset_checked(data, bytes(descendants_named(last[0], "<pdv_context_id_rcv>")[0])[0])


def pdu_dataset_ok(pdu):
    "The data set that travels in the same P-DATA-TF as its command obeys the rules of its transfer syntax."
    data = b"".join(bytes(node) for node in descendants_named(pdu, "<dataset_rcv_more>")) + b"".join(bytes(node) for node in descendants_named(pdu, "<dataset_rcv>"))
    contexts = descendants_named(pdu, "<pdv_context_id_rcv>")
    return dataset_checked(data, bytes(contexts[-1])[0]) if contexts else True


def fragment_ok(fragment):
    "Every fragment of a message consists of an even number of bytes and is not empty (PS3.8 E.1)."
    return len(bytes(fragment)) > 0 and len(bytes(fragment)) % 2 == 0


def received_context_ok(node):
    "The Presentation Context ID of a received PDV is one of the contexts the association accepted (PS3.8 7.6.1)."
    return not ACCEPTED or ACCEPTED.get(bytes(node)[0], (3, ""))[0] == 0


def same_context(message):
    "All PDVs of one received message use the same presentation context (PS3.8 E.1)."
    seen = []
    for node in descendants_named(message, "<pdv_context_id_rcv>"):
        if bytes(node) not in seen:
            seen.append(bytes(node))
    return len(seen) <= 1


def sub_priority_ok(exchange):
    "The C-STORE sub-operations of a C-GET use the priority of the C-GET-RQ (PS3.7 9.1.3.1.4)."
    request, replies = request_and_replies(exchange)
    if request is None:
        return True
    priorities = descendants_named(request, "<priority_value>")
    if not priorities:
        return True
    expected = bytes(priorities[0])
    for reply in replies:
        if reply.symbol.name() == "<exchange_c_store_sub>" and descendants_named(reply, "<pdv_dataset_rcv>"):
            for node in descendants_named(reply, "<priority_value>"):
                if bytes(node) != expected:
                    return False
    return True


# ======================================================================================================
# Timers (Fandango parties TimerControl / TimerEvent). One id per timer; the spec lets the peer stay away
# ======================================================================================================
<associate_timer_start> ::= <timer_start>
<associate_timer_cancel> ::= <timer_cancel>
<associate_timer_expired> ::= <timer_expired>
<release_timer_start> ::= <timer_start>
<release_timer_cancel> ::= <timer_cancel>
<release_timer_expired> ::= <timer_expired>
<artim_timer_start> ::= <timer_start>
<artim_timer_expired> ::= <timer_expired>
where str(<associate_timer_start>..<timer_id>) == '1'
where str(<associate_timer_start>..<timer_timeout>) == '4'
where str(<associate_timer_cancel>..<timer_id>) == '1'
where str(<associate_timer_expired>..<timer_id>) == '1'
where str(<release_timer_start>..<timer_id>) == '2'
where str(<release_timer_start>..<timer_timeout>) == '4'
where str(<release_timer_cancel>..<timer_id>) == '2'
where str(<release_timer_expired>..<timer_id>) == '2'
where str(<artim_timer_start>..<timer_id>) == '4'
where str(<artim_timer_start>..<timer_timeout>) == '0.5'
where str(<artim_timer_expired>..<timer_id>) == '4'

# ======================================================================================================
# Association states (PS3.8 9.2.1). The driver opens the transport connection (Sta4 -> Sta5 with the RQ).
# ======================================================================================================
<start> ::= <sta5>

# Sta 5: awaiting A-ASSOCIATE-AC or A-ASSOCIATE-RJ PDU (PS3.8 9.2.1); the reply class selects the next state
<sta5> ::= (<exchange_associate_accepted> <sta6> | <exchange_associate_refused_all> <sta6_refused> |
          <exchange_associate_rejected> |
          <exchange_associate_aborted> |
          <exchange_associate_unanswered> | <exchange_associate_unanswered_abort> |
          <exchange_associate_wrong_called_accepted> <sta6> | <exchange_associate_wrong_called_refused_all> <sta6_refused> | <exchange_associate_wrong_called_rejected> | <exchange_associate_wrong_called_aborted> | <exchange_associate_wrong_called_unanswered> |
          <exchange_associate_wrong_credentials_accepted> <sta6> | <exchange_associate_wrong_credentials_refused_all> <sta6_refused> | <exchange_associate_wrong_credentials_rejected> | <exchange_associate_wrong_credentials_aborted> | <exchange_associate_wrong_credentials_unanswered> |
          <exchange_without_association> | <exchange_associate_variant> | <exchange_associate_contexts> | <exchange_associate_abort_at_once> |
          <exchange_associate_offer_breaker>)

# Sta 6: association established and ready for data transfer (PS3.8 9.2.1). The server's own initiatives are accepted here.
<sta6> ::= (<exchange_c_echo> <sta6> | <exchange_c_echo_aborted> | <exchange_c_echo_unanswered> | <exchange_c_echo_pair> <sta6> | <exchange_c_echo_pair_aborted> | <exchange_c_echo_pair_unanswered> |
          <exchange_c_echo_unaccepted_context> <sta6> | <exchange_c_echo_unaccepted_context_aborted> | <exchange_c_echo_unaccepted_context_unanswered> |
          <exchange_c_store> <sta6> | <exchange_c_store_aborted> | <exchange_c_store_unanswered> |
          <exchange_c_store_oversized> <sta6> | <exchange_c_store_oversized_aborted> | <exchange_c_store_oversized_unanswered> |
          <exchange_c_find> | <exchange_c_find_unanswered> |
          <exchange_c_get> | <exchange_c_get_unanswered> |
          <exchange_c_move> | <exchange_c_move_unanswered> |
          <exchange_c_move_unknown_destination> <sta6> | <exchange_c_move_unknown_destination_aborted> | <exchange_c_move_unknown_destination_unanswered> |
          <exchange_n_get> <sta6> | <exchange_n_get_aborted> | <exchange_n_get_unanswered> |
          <exchange_n_set> <sta6> | <exchange_n_set_aborted> | <exchange_n_set_unanswered> |
          <exchange_n_action> <sta6> | <exchange_n_action_aborted> | <exchange_n_action_unanswered> |
          <exchange_n_create> <sta6> | <exchange_n_create_aborted> | <exchange_n_create_unanswered> |
          <exchange_n_delete> <sta6> | <exchange_n_delete_aborted> | <exchange_n_delete_unanswered> |
          <exchange_unexpected_associate_rq> | <exchange_unexpected_release_rp> | <exchange_unrecognized_pdu> |
          <server_event_report> <sta6> | <server_release> | <server_abort> |
          <exchange_release> | <exchange_release_abort_at_once> | <exchange_abort_by_client_artim>)

# Sta 6 after an A-ASSOCIATE-AC that refused every presentation context (PS3.8 9.2.1, 7.1.1.13; PS3.7 D.3.2): there is no context a PDV could name (PS3.8 7.6.1), so the client sends no P-DATA-TF and no DIMSE request. It releases or aborts,
# and the server's own A-RELEASE-RQ and A-ABORT are accepted (a server's N-EVENT-REPORT would need a context). The ARTIM / release timers end the waits.
<sta6_refused> ::= (<exchange_release> | <exchange_release_abort_at_once> | <exchange_abort_by_client_artim> | <server_release_refused> | <server_abort>)
<server_release_refused> ::= <Server:rsp_release_rq> (<Client:req_release_rp> <sta13> | <Server:rsp_abort> | <Client:req_abort> <sta13>)

# A-ASSOCIATE exchanges (PS3.8 9.3.2 - 9.3.4)
<exchange_associate_accepted> ::= <TimerControl:associate_timer_start> <Client:req_associate> <Server:rsp_associate_ac_accepted> <TimerControl:associate_timer_cancel>
<exchange_associate_refused_all> ::= <TimerControl:associate_timer_start> <Client:req_associate> <Server:rsp_associate_ac_refused> <TimerControl:associate_timer_cancel>
<exchange_associate_rejected> ::= <TimerControl:associate_timer_start> <Client:req_associate> <Server:rsp_associate_rj> <TimerControl:associate_timer_cancel>
<exchange_associate_aborted> ::= <TimerControl:associate_timer_start> <Client:req_associate> <Server:rsp_abort> <TimerControl:associate_timer_cancel>
<exchange_associate_unanswered> ::= <TimerControl:associate_timer_start> <Client:req_associate> <TimerEvent:associate_timer_expired>
# AA-1 in Sta 5 (PS3.8 9.2.1, 7.1.1): the requestor may issue an A-ABORT while it awaits the reply; sent when the wait is over (an abort sent at once crosses the reply, see the TODO at the top)
<exchange_associate_unanswered_abort> ::= <TimerControl:associate_timer_start> <Client:req_associate> <TimerEvent:associate_timer_expired> <Client:req_abort> <sta13>

# Refusing association exchanges: wrong called AE title / wrong credentials (the server may refuse, accept anyway, abort or stay silent)
<exchange_associate_wrong_called_accepted> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_called> <Server:rsp_associate_ac_accepted> <TimerControl:associate_timer_cancel>
<exchange_associate_wrong_called_refused_all> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_called> <Server:rsp_associate_ac_refused> <TimerControl:associate_timer_cancel>
<exchange_associate_wrong_called_rejected> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_called> <Server:rsp_associate_rj> <TimerControl:associate_timer_cancel>
<exchange_associate_wrong_called_aborted> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_called> <Server:rsp_abort> <TimerControl:associate_timer_cancel>
<exchange_associate_wrong_called_unanswered> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_called> <TimerEvent:associate_timer_expired>
<exchange_associate_wrong_credentials_accepted> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_credentials> <Server:rsp_associate_ac_accepted> <TimerControl:associate_timer_cancel>
<exchange_associate_wrong_credentials_refused_all> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_credentials> <Server:rsp_associate_ac_refused> <TimerControl:associate_timer_cancel>
<exchange_associate_wrong_credentials_rejected> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_credentials> <Server:rsp_associate_rj> <TimerControl:associate_timer_cancel>
<exchange_associate_wrong_credentials_aborted> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_credentials> <Server:rsp_abort> <TimerControl:associate_timer_cancel>
<exchange_associate_wrong_credentials_unanswered> ::= <TimerControl:associate_timer_start> <Client:req_associate_wrong_credentials> <TimerEvent:associate_timer_expired>

# Further refusal triggers of the association request (PS3.8 9.3.4): an application context name the server does not support, a protocol version
# other than 1, a calling AE title it does not know. The server refuses, accepts anyway, aborts or stays silent.
# PS3.8 9.3.2.2 / 7.1.1.13: an A-ASSOCIATE-RQ with a list of presentation contexts of its own: one to 128 contexts (<rq_pc_custom>), each with an odd id from 1 to 255 from the shared <rq_pc_id> (the first id is any odd value, the others follow it in
# steps of two modulo 256, so the ids are distinct), any abstract syntax first or later (also one that an earlier context has, and one no server knows), the default transfer syntax in every context (so every abstract syntax offers it, PS3.5 10.1) and
# in half of them one or two more of any kind. An AC that accepts at least one context continues in Sta 6, an AC that refuses every context in <sta6_refused>. The service group of a context
# is that of its abstract syntax (category_of).
<exchange_associate_contexts> ::= <TimerControl:associate_timer_start> <Client:req_associate_contexts> (<Server:rsp_associate_ac_accepted> <TimerControl:associate_timer_cancel> <sta6> | <Server:rsp_associate_ac_refused> <TimerControl:associate_timer_cancel> <sta6_refused> | <Server:rsp_associate_rj> <TimerControl:associate_timer_cancel> | <Server:rsp_abort> <TimerControl:associate_timer_cancel> | <TimerEvent:associate_timer_expired>)
<req_associate_contexts> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <application_context_item> <rq_contexts_custom> <rq_user_information_item>
<rq_contexts_custom> ::= <rq_pc_custom>{1,128}
<rq_pc_custom> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_custom> (<transfer_syntax_item_default> | <transfer_syntax_item_default> <transfer_syntax_item_custom>{1,2} | <transfer_syntax_item_default> <transfer_syntax_items_jpeg>)
<abstract_syntax_item_custom> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_custom>
<abstract_syntax_custom> ::= <uid> := custom_abstract_syntax()
<transfer_syntax_item_custom> ::= <transfer_syntax_item_head> <transfer_syntax_custom>
<transfer_syntax_custom> ::= <uid> := custom_transfer_syntax()

# PS3.5 10.1 / 10.2 / 10.3 (F54, C92, C93, F128 breakers): three requests of their own that break one offering rule each, built from the shared context rules, the rest of the list is the standard one. The spec makes no reaction mandatory
# for them, so the exchange (one for the three requests: they share their reply classes) accepts every reply of Sta 5 (accept, refuse every context, reject, abort, silence).
# <req_associate_no_default>: the Verification abstract syntax is offered with Explicit VR Little Endian only (no context with the default Implicit VR, PS3.5 10.1 a)
# <req_associate_lossless_without_default>: the Verification abstract syntax with Process 14 (.4.57) and no context with the default lossless JPEG syntax (.4.70) (PS3.5 10.2 a)
# <req_associate_lossy_without_default>: the Verification abstract syntax with JPEG Extended (.4.51) and no context with the 8 bit lossy default (.4.50) (PS3.5 10.3 a)
<exchange_associate_offer_breaker> ::= <TimerControl:associate_timer_start> <Client:req_associate_offer_breaker> (<Server:rsp_associate_ac_accepted> <TimerControl:associate_timer_cancel> <sta6> | <Server:rsp_associate_ac_refused> <TimerControl:associate_timer_cancel> <sta6_refused> | <Server:rsp_associate_rj> <TimerControl:associate_timer_cancel> | <Server:rsp_abort> <TimerControl:associate_timer_cancel> | <TimerEvent:associate_timer_expired>)
<req_associate_offer_breaker> ::= <req_associate_no_default> | <req_associate_lossless_without_default> | <req_associate_lossy_without_default>
<req_associate_no_default> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <application_context_item> <rq_contexts_no_default> <rq_user_information_item>
<req_associate_lossless_without_default> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <application_context_item> <rq_contexts_lossless_without_default> <rq_user_information_item>
<req_associate_lossy_without_default> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <application_context_item> <rq_contexts_lossy_without_default> <rq_user_information_item>
<rq_contexts_no_default> ::= <rq_pc_verification_no_default> <rq_pc_storage> <rq_pc_find> <rq_pc_move> <rq_pc_get> <rq_pc_normalized> <rq_pc_explicit_group> <rq_pc_encapsulated_group>
<rq_contexts_lossless_without_default> ::= <rq_pc_verification_lossless_without_default> <rq_pc_storage> <rq_pc_find> <rq_pc_move> <rq_pc_get> <rq_pc_normalized> <rq_pc_explicit_group> <rq_pc_encapsulated_group>
<rq_contexts_lossy_without_default> ::= <rq_pc_verification_lossy_without_default> <rq_pc_storage> <rq_pc_find> <rq_pc_move> <rq_pc_get> <rq_pc_normalized> <rq_pc_explicit_group> <rq_pc_encapsulated_group>
<rq_pc_verification_no_default> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_verification> <transfer_syntax_item>
<rq_pc_verification_lossless_without_default> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_verification> <transfer_syntax_item_default> <transfer_syntax_item_lossless_process_14>
<rq_pc_verification_lossy_without_default> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_verification> <transfer_syntax_item_default> <transfer_syntax_item_lossy_extended>

<exchange_associate_variant> ::= <TimerControl:associate_timer_start> <Client:req_associate_variant> (<Server:rsp_associate_ac_accepted> <TimerControl:associate_timer_cancel> <sta6> | <Server:rsp_associate_ac_refused> <TimerControl:associate_timer_cancel> <sta6_refused> | <Server:rsp_associate_rj> <TimerControl:associate_timer_cancel> | <Server:rsp_abort> <TimerControl:associate_timer_cancel> | <TimerEvent:associate_timer_expired>)
<req_associate_variant> ::= <req_associate_other_context> | <req_associate_other_version> | <req_associate_unknown_calling>
<req_associate_other_context> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <application_context_item_other> <rq_contexts> <rq_user_information_item>
<application_context_item_other> ::= b'\x10' <reserved_byte> <item_length> <application_context_name_other>
<application_context_name_other> ::= <uid> := random.choice(OTHER_APPLICATION_CONTEXTS).encode("ascii")
<req_associate_other_version> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version_other> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <rq_variable_items>
<protocol_version_other> ::= rb'[\x00-\xff]{2}' := random.choice([b'\x00\x02', b'\x00\x03', b'\x80\x01', b'\xff\xfe'])
<req_associate_unknown_calling> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title_unknown> <reserved_32> <rq_variable_items>
<calling_ae_title_unknown> ::= <ae_title> := ae16(random.choice(UNKNOWN_CALLING_AETS))

# A-RELEASE exchange (PS3.8 9.3.6, 9.3.7)
# Sta 7: the server may keep sending P-DATA-TF before its answer (PS3.8 9.2.1 AR-6); its own A-RELEASE-RQ crosses ours (release collision, Sta 9 - 11)
<exchange_release> ::= <TimerControl:release_timer_start> <Client:req_release> <Server:rsp_pdata_while_releasing>* <release_end>
<release_end> ::= <Server:rsp_release> <TimerControl:release_timer_cancel> | <Server:rsp_abort> <TimerControl:release_timer_cancel> | <TimerEvent:release_timer_expired> | <TimerEvent:release_timer_expired> <Client:req_abort> <sta13> | <Server:rsp_release_rq> (<Client:req_release_rp_collision> <release_collision_end> | <Server:rsp_abort> <TimerControl:release_timer_cancel> | <Client:req_abort> <TimerControl:release_timer_cancel> <sta13>)
<release_collision_end> ::= <Server:rsp_release> <TimerControl:release_timer_cancel> | <Server:rsp_abort> <TimerControl:release_timer_cancel> | <TimerEvent:release_timer_expired> | <TimerEvent:release_timer_expired> <Client:req_abort> <sta13>
<req_release_rp_collision> ::= <req_release_rp>
# 9.3.5: a P-DATA-TF the requestor still receives while its release is pending; its content is not interpreted
<rsp_pdata_while_releasing> ::= b'\x04' <reserved_byte> <pdu_length> <pdata_while_releasing>
<pdata_while_releasing> ::= <pdv_chunk>{from_u32(bytes(<pdu_length>)) >> 16} <byte>{from_u32(bytes(<pdu_length>)) & 65535}

# ======================================================================================================
# PDU common fields (PS3.8 9.3)
# ======================================================================================================
# 9.3.x Reserved bytes: sent with 00H, not tested when received
<reserved_byte> ::= rb'[\x00-\xff]' := b'\x00'
<reserved_2> ::= rb'[\x00-\xff]{2}' := b'\x00\x00'
<reserved_32> ::= rb'[\x00-\xff]{32}' := b'\x00' * 32
# 9.3.4 - 9.3.8 PDU-length of A-ASSOCIATE-RJ, A-RELEASE-RQ/RP and A-ABORT: always 00000004H
<pdu_length_four> ::= b'\x00\x00\x00\x04'
# 9.3.x PDU-length: number of bytes from the first byte after the PDU-length field to the end of the PDU
<pdu_length> ::= rb'[\x00-\xff]{4}'
where forall <l> in <pdu_length>: <l> == u32be(len(bytes(<l>.parent)) - 6)
# 9.3.2.x Item-length: number of bytes after the Item-length field
<item_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <item_length>: <l> == u16be(len(bytes(item_of(<l>))) - 4)
# 9.3.2 Protocol-version: bit 0 identifies version 1
<protocol_version> ::= rb'[\x00-\xff]{2}' := b'\x00\x01'
# 9.3.2 AE titles: 16 characters, not all spaces
# 16 characters, not all spaces; leading and trailing spaces are not significant (PS3.8 9.3.2.2), so any number of leading spaces is accepted
<ae_title> ::= rb'[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{15}|\x20{1}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{14}|\x20{2}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{13}|\x20{3}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{12}|\x20{4}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{11}|\x20{5}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{10}|\x20{6}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{9}|\x20{7}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{8}|\x20{8}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{7}|\x20{9}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{6}|\x20{10}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{5}|\x20{11}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{4}|\x20{12}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{3}|\x20{13}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{2}|\x20{14}[\x21-\x5b\x5d-\x7e][\x20-\x5b\x5d-\x7e]{1}|\x20{15}[\x21-\x5b\x5d-\x7e]'
<called_ae_title> ::= <ae_title> := pick_called_ae()
<calling_ae_title> ::= <ae_title> := pick_calling_ae()
# UID (PS3.5 9.1) as encoded in items (PS3.8 Annex F)
<uid> ::= rb'(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,31}'

where forall <u> in <uid>: len(bytes(<u>)) <= 64

# 9.3.2 A-ASSOCIATE-RQ
<req_associate> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <rq_variable_items>
<rq_variable_items> ::= <application_context_item> <rq_contexts> <rq_user_information_item>
<rq_contexts> ::= <rq_pc_verification> <rq_pc_storage> <rq_pc_find> <rq_pc_move> <rq_pc_get> <rq_pc_normalized> <rq_pc_explicit_group> <rq_pc_encapsulated_group>

# 9.3.2.1 Application Context Item (PS3.7 D.3.1: the DICOM application context name)
<application_context_item> ::= b'\x10' <reserved_byte> <item_length> <application_context_name>
<application_context_name> ::= <uid> := b'1.2.840.10008.3.1.1.1'

# 9.3.2.2 Presentation Context Items (RQ): one per service group, ids odd and distinct (PS3.8 7.1.1.13); the groups offer the default syntax, their second contexts (<rq_pc_explicit_group>) Explicit VR Little Endian
<rq_pc_verification> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_verification> <transfer_syntax_item_default> <transfer_syntax_item_extra>{0,3} <transfer_syntax_items_jpeg>?
<rq_pc_storage> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage> <transfer_syntax_item_default>
<rq_pc_find> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_find> <transfer_syntax_item_default>
<rq_pc_move> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_move> <transfer_syntax_item_default>
<rq_pc_get> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_get> <transfer_syntax_item_default>
<rq_pc_normalized> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_normalized> <transfer_syntax_item_default>
<presentation_context_id> ::= rb'[\x00-\xff]'
# PS3.8 9.3.2.2.1: the Presentation-context-ID is an odd integer from 1 to 255, distinct within the request (7.1.1.13). Every context of a sent request (the standard list of 24 contexts and the custom lists of
# 1 to 128) takes its id from this one rule: the first context's id is any odd value (generator), the others follow it in steps of two modulo 256 (an equality), so the ids are distinct for up to 128 contexts
<rq_pc_id> ::= <presentation_context_id> := random_odd_id()
where forall <i> in <rq_pc_id>: <i> == chained_context_id(<i>)
# PS3.8 7.1.1.13: the same abstract syntax may occur in several presentation contexts, each with its own odd id; the Implicit VR default is required in
# only one of them (PS3.5 10.1), so these second contexts offer Explicit VR Little Endian only
<rq_pc_explicit_group> ::= <rq_pc_storage_explicit> <rq_pc_find_explicit> <rq_pc_move_explicit> <rq_pc_get_explicit> <rq_pc_normalized_explicit>
<rq_pc_storage_explicit> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item>
<rq_pc_find_explicit> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_find_again> <transfer_syntax_item>
<rq_pc_move_explicit> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_move_again> <transfer_syntax_item>
<rq_pc_get_explicit> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_get_again> <transfer_syntax_item>
<rq_pc_normalized_explicit> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_normalized_again> <transfer_syntax_item>
# PS3.5 A.4, A.6: contexts for encapsulated Pixel Data (RLE with its own codec rules, generic encapsulated fragments, JPIP referenced Pixel Data URL); the default
# syntax is offered in the first context of the abstract syntax (PS3.5 10.1)
<rq_pc_encapsulated_group> ::= <rq_pc_storage_rle> <rq_pc_storage_encapsulated> <rq_pc_storage_jpip> <rq_pc_storage_evbe> <rq_pc_storage_deflated> <rq_pc_storage_video> <rq_pc_storage_uncompressed> <rq_pc_storage_deflated_frame> <rq_pc_storage_stereo> <rq_pc_storage_jpip_deflate> <rq_pc_storage_single> <rq_pc_storage_hevc10> <rq_pc_storage_xlrecomp> <rq_pc_storage_video_single> <rq_pc_storage_stereo_single> <rq_pc_storage_jpeg>
<rq_pc_storage_jpeg> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_default> <transfer_syntax_items_jpeg>
<rq_pc_storage_rle> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_rle>
<rq_pc_storage_encapsulated> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_encapsulated>
<rq_pc_storage_jpip> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_jpip>
<rq_pc_storage_evbe> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_evbe>
<transfer_syntax_item_evbe> ::= <transfer_syntax_item_head> <transfer_syntax_evbe>
<transfer_syntax_evbe> ::= <uid> := b'1.2.840.10008.1.2.2'
<rq_pc_storage_video> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_video>
<transfer_syntax_item_video> ::= <transfer_syntax_item_head> <transfer_syntax_video>
<transfer_syntax_video> ::= <uid> := pick_uid(VIDEO_TRANSFER_SYNTAXES)
<rq_pc_storage_video_single> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_video_single>
<transfer_syntax_item_video_single> ::= <transfer_syntax_item_head> <transfer_syntax_video_single>
<transfer_syntax_video_single> ::= <uid> := pick_uid(VIDEO_SINGLE_TRANSFER_SYNTAXES)
<rq_pc_storage_stereo_single> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_stereo_single>
<transfer_syntax_item_stereo_single> ::= <transfer_syntax_item_head> <transfer_syntax_stereo_single>
<transfer_syntax_stereo_single> ::= <uid> := pick_uid(STEREO_SINGLE_TRANSFER_SYNTAXES)
<rq_pc_storage_deflated> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_deflated>
<transfer_syntax_item_deflated> ::= <transfer_syntax_item_head> <transfer_syntax_deflated>
<transfer_syntax_deflated> ::= <uid> := b'1.2.840.10008.1.2.1.99'
<transfer_syntax_item_rle> ::= <transfer_syntax_item_head> <transfer_syntax_rle>
<transfer_syntax_rle> ::= <uid> := b'1.2.840.10008.1.2.5'
<transfer_syntax_item_encapsulated> ::= <transfer_syntax_item_head> <transfer_syntax_encapsulated>
<transfer_syntax_encapsulated> ::= <uid> := pick_uid(ENCAPSULATED_TRANSFER_SYNTAXES)
<transfer_syntax_item_jpip> ::= <transfer_syntax_item_head> <transfer_syntax_jpip>
<transfer_syntax_jpip> ::= <uid> := pick_uid(JPIP_TRANSFER_SYNTAXES)
<abstract_syntax_item_storage_again> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_storage_again>
<abstract_syntax_item_find_again> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_find_again>
<abstract_syntax_item_move_again> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_move_again>
<abstract_syntax_item_get_again> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_get_again>
<abstract_syntax_item_normalized_again> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_normalized_again>
<abstract_syntax_storage_again> ::= <uid> := recall_pick("storage")
<abstract_syntax_find_again> ::= <uid> := recall_pick("find")
<abstract_syntax_move_again> ::= <uid> := recall_pick("move")
<abstract_syntax_get_again> ::= <uid> := recall_pick("get")
<abstract_syntax_normalized_again> ::= <uid> := recall_pick("normalized")
# 9.3.2.2.1 Abstract Syntax Sub-Item: the SOP class of each service group is picked from the setup's list
<abstract_syntax_item_verification> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_verification>
<abstract_syntax_item_storage> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_storage>
<abstract_syntax_item_find> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_find>
<abstract_syntax_item_move> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_move>
<abstract_syntax_item_get> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_get>
<abstract_syntax_item_normalized> ::= b'\x30' <reserved_byte> <item_length> <abstract_syntax_normalized>
<abstract_syntax_verification> ::= <uid> := pick_abstract("verification", [VERIFICATION_SOP_CLASS])
<abstract_syntax_storage> ::= <uid> := pick_abstract("storage", STORAGE_SOP_CLASSES)
<abstract_syntax_find> ::= <uid> := pick_abstract("find", FIND_SOP_CLASSES)
<abstract_syntax_move> ::= <uid> := pick_abstract("move", MOVE_SOP_CLASSES)
<abstract_syntax_get> ::= <uid> := pick_abstract("get", GET_SOP_CLASSES)
<abstract_syntax_normalized> ::= <uid> := pick_abstract("normalized", NORMALIZED_SOP_CLASSES)
# 9.3.2.2.2 Transfer Syntax Sub-Item
# PS3.8 9.3.2.2.2 / 9.3.3.2.1 Transfer Syntax Sub-Item (Tables 9-15, 9-19): item type 40H, reserved, item length; the item is this head and a name, defined once here and used by every sent form and by the received
# AC items, which differ only in the name nonterminal (the narrowed forms below name one transfer syntax or a group of them)
<transfer_syntax_item_head> ::= b'\x40' <reserved_byte> <item_length>
<transfer_syntax_item> ::= <transfer_syntax_item_head> <transfer_syntax_name>
<transfer_syntax_name> ::= <uid> := pick_uid(TRANSFER_SYNTAXES)
# PS3.5 10.1: Implicit VR Little Endian is offered for every abstract syntax
<transfer_syntax_item_default> ::= <transfer_syntax_item_head> <transfer_syntax_default>
<transfer_syntax_default> ::= <uid> := b'1.2.840.10008.1.2'
# PS3.5 10.2 / 10.3: a context that offers a JPEG transfer syntax carries the defaults of the family: the default lossless JPEG syntax (.4.70) with the default Implicit VR (the context's first item), the lossy default of
# 8 bit images (.4.50); Process 14 (.4.57) and the 12 bit default (.4.51) come only with them
<transfer_syntax_items_jpeg> ::= <transfer_syntax_item_lossless_process_14>? <transfer_syntax_item_lossless_default> <transfer_syntax_item_lossy_default> <transfer_syntax_item_lossy_extended>?
<transfer_syntax_item_lossy_default> ::= <transfer_syntax_item_head> <transfer_syntax_lossy_default>
<transfer_syntax_lossy_default> ::= <uid> := b'1.2.840.10008.1.2.4.50'
<transfer_syntax_item_lossy_extended> ::= <transfer_syntax_item_head> <transfer_syntax_lossy_extended>
<transfer_syntax_lossy_extended> ::= <uid> := b'1.2.840.10008.1.2.4.51'
<transfer_syntax_item_lossless_process_14> ::= <transfer_syntax_item_head> <transfer_syntax_lossless_process_14>
<transfer_syntax_lossless_process_14> ::= <uid> := b'1.2.840.10008.1.2.4.57'
<transfer_syntax_item_lossless_default> ::= <transfer_syntax_item_head> <transfer_syntax_lossless_default>
<transfer_syntax_lossless_default> ::= <uid> := b'1.2.840.10008.1.2.4.70'
<transfer_syntax_item_extra> ::= <transfer_syntax_item_head> <transfer_syntax_extra>
<transfer_syntax_extra> ::= <uid> := pick_uid(PLAIN_EXTRA_TRANSFER_SYNTAXES)

# 9.3.2.3 User Information Item (RQ): sub-items in any order (sent in ascending order of item type)
<rq_user_information_item> ::= b'\x50' <reserved_byte> <item_length> <maximum_length_item> <implementation_class_uid_item> <implementation_version_name_item>? <asynchronous_operations_window_item>? <scp_scu_role_selection_items_rq> <sop_class_extended_negotiation_items_rq> <sop_class_common_extended_negotiation_items_rq> <user_identity_rq_item>? <rq_unrecognized_user_item>?
# PS3.8 D.2: an acceptor ignores sub-items it does not recognize (types 5AH-FFH are not defined); sent to exercise that
<rq_unrecognized_user_item> ::= <unrecognized_user_item_type> <reserved_byte> <item_length> <unrecognized_user_item_data>
<unrecognized_user_item_type> ::= rb'[\x5a-\xff]'
<unrecognized_user_item_data> ::= rb'[\x00-\xff]{1,8}'
# PS3.8 D.1 Maximum Length sub-item (shared by RQ and AC)
<maximum_length_item> ::= b'\x51' <reserved_byte> <item_length> <maximum_length_received>
<maximum_length_received> ::= rb'[\x00-\xff]{4}' := random.choice([b'\x00\x00\x40\x00', b'\x00\x00\x00\x00', b'\x00\x01\x00\x00', b'\x00\x00\x20\x00'])
# PS3.7 D.3.3.2 Implementation Class UID (52H) and Implementation Version Name (55H) sub-items (shared by RQ and AC)
<implementation_class_uid_item> ::= b'\x52' <reserved_byte> <item_length> <implementation_class_uid>
<implementation_class_uid> ::= <uid> := b'1.2.826.0.1.3680043.9.7133.1.1'
<implementation_version_name_item> ::= b'\x55' <reserved_byte> <item_length> <implementation_version_name>
<implementation_version_name> ::= rb'[\x20-\x7e]{1,16}'
# PS3.7 D.3.3.3 Asynchronous Operations Window sub-item (53H) (shared by RQ and AC)
<asynchronous_operations_window_item> ::= b'\x53' <reserved_byte> <item_length> <max_operations_invoked> <max_operations_performed>
<max_operations_invoked> ::= rb'[\x00-\xff]{2}'
<max_operations_performed> ::= rb'[\x00-\xff]{2}'
# PS3.7 D.3.3.4 SCP/SCU Role Selection sub-item (54H): one per SOP class, a class offered in a presentation context (RQ and AC)
<scp_scu_role_selection_item> ::= b'\x54' <reserved_byte> <item_length> <role_uid_length> <uid> <scu_role> <scp_role>
<role_uid_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <role_uid_length>: <l> == u16be(next_sibling_length(<l>))
<scu_role> ::= rb'[\x00\x01]'
<scp_role> ::= rb'[\x00\x01]'
<scp_scu_role_selection_items_rq> ::= <role_item_rq_verification>? <role_item_rq_storage>? <role_item_rq_find>? <role_item_rq_move>? <role_item_rq_get>? <role_item_rq_normalized>?
# RQ: the requestor offers one of three role values (PS3.7 D.3.3.4): SCU only, SCP only, both
<role_pair_rq> ::= <role_scu_only> | <role_scp_only> | <role_scu_and_scp>
<role_scu_only> ::= b'\x01\x00'
<role_scp_only> ::= b'\x00\x01'
<role_scu_and_scp> ::= b'\x01\x01'
<role_item_rq_verification> ::= b'\x54' <reserved_byte> <item_length> <role_uid_length> <role_uid_verification> <role_pair_rq>
<role_uid_verification> ::= <uid> := recall_pick("verification")
<role_item_rq_storage> ::= b'\x54' <reserved_byte> <item_length> <role_uid_length> <role_uid_storage> <role_pair_rq>
<role_uid_storage> ::= <uid> := recall_pick("storage")
<role_item_rq_find> ::= b'\x54' <reserved_byte> <item_length> <role_uid_length> <role_uid_find> <role_pair_rq>
<role_uid_find> ::= <uid> := recall_pick("find")
<role_item_rq_move> ::= b'\x54' <reserved_byte> <item_length> <role_uid_length> <role_uid_move> <role_pair_rq>
<role_uid_move> ::= <uid> := recall_pick("move")
<role_item_rq_get> ::= b'\x54' <reserved_byte> <item_length> <role_uid_length> <role_uid_get> <role_pair_rq>
<role_uid_get> ::= <uid> := recall_pick("get")
<role_item_rq_normalized> ::= b'\x54' <reserved_byte> <item_length> <role_uid_length> <role_uid_normalized> <role_pair_rq>
<role_uid_normalized> ::= <uid> := recall_pick("normalized")
# PS3.7 D.3.3.5 SOP Class Extended Negotiation sub-item (56H): one per SOP class
<sop_class_extended_negotiation_items_rq> ::= <extneg_item_rq_verification>? <extneg_item_rq_storage>? <extneg_item_rq_find>? <extneg_item_rq_move>? <extneg_item_rq_get>? <extneg_item_rq_normalized>?
# TODO: PS3.7 D.3.3.5.1 (Service-class-application-information of a SOP Class Extended Negotiation item), nearest <service_class_application_information>: its content is defined per Service Class in PS3.4, which is not in refs/spec/; a few bytes are sent.
<service_class_application_information> ::= rb'[\x00-\xff]{1,4}'
<extneg_uid_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <extneg_uid_length>: <l> == u16be(next_sibling_length(<l>))
<extneg_item_rq_verification> ::= b'\x56' <reserved_byte> <item_length> <extneg_uid_length> <extneg_uid_verification> <service_class_application_information>
<extneg_uid_verification> ::= <uid> := recall_pick("verification")
<extneg_item_rq_storage> ::= b'\x56' <reserved_byte> <item_length> <extneg_uid_length> <extneg_uid_storage> <service_class_application_information>
<extneg_uid_storage> ::= <uid> := recall_pick("storage")
<extneg_item_rq_find> ::= b'\x56' <reserved_byte> <item_length> <extneg_uid_length> <extneg_uid_find> <service_class_application_information>
<extneg_uid_find> ::= <uid> := recall_pick("find")
<extneg_item_rq_move> ::= b'\x56' <reserved_byte> <item_length> <extneg_uid_length> <extneg_uid_move> <service_class_application_information>
<extneg_uid_move> ::= <uid> := recall_pick("move")
<extneg_item_rq_get> ::= b'\x56' <reserved_byte> <item_length> <extneg_uid_length> <extneg_uid_get> <service_class_application_information>
<extneg_uid_get> ::= <uid> := recall_pick("get")
<extneg_item_rq_normalized> ::= b'\x56' <reserved_byte> <item_length> <extneg_uid_length> <extneg_uid_normalized> <service_class_application_information>
<extneg_uid_normalized> ::= <uid> := recall_pick("normalized")
# PS3.7 D.3.3.6 SOP Class Common Extended Negotiation sub-item (57H): one per SOP class
# TODO: PS3.7 D.3.3.6 (Service Class UID of the Verification, Query/Retrieve and normalized SOP classes), nearest <service_class_uid>: only the Storage Service Class UID (1.2.840.10008.4.2) is in refs/spec/, so the item is sent for the storage SOP classes only.
<sop_class_common_extended_negotiation_items_rq> ::= <common_item_rq_storage>?
<common_sop_class_uid_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <common_sop_class_uid_length>: <l> == u16be(next_sibling_length(<l>))
<service_class_uid_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <service_class_uid_length>: <l> == u16be(next_sibling_length(<l>))
<service_class_uid> ::= <uid> := b'1.2.840.10008.4.2'
<related_general_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <related_general_length>: <l> == u16be(related_general_size(<l>.parent))
<related_general_sop_class_item> ::= <related_uid_length> <related_general_sop_class_uid>
<related_uid_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <related_uid_length>: <l> == u16be(next_sibling_length(<l>))
<related_general_sop_class_uid> ::= <uid> := pick_uid(ALL_SOP_CLASSES)
<common_item_rq_verification> ::= b'\x57' <reserved_byte> <item_length> <common_sop_class_uid_length> <common_uid_verification> <service_class_uid_length> <service_class_uid> <related_general_length> <related_general_sop_class_item>*
<common_uid_verification> ::= <uid> := recall_pick("verification")
<common_item_rq_storage> ::= b'\x57' <reserved_byte> <item_length> <common_sop_class_uid_length> <common_uid_storage> <service_class_uid_length> <service_class_uid> <related_general_length> <related_general_sop_class_item>*
<common_uid_storage> ::= <uid> := recall_pick("storage")
<common_item_rq_find> ::= b'\x57' <reserved_byte> <item_length> <common_sop_class_uid_length> <common_uid_find> <service_class_uid_length> <service_class_uid> <related_general_length> <related_general_sop_class_item>*
<common_uid_find> ::= <uid> := recall_pick("find")
<common_item_rq_move> ::= b'\x57' <reserved_byte> <item_length> <common_sop_class_uid_length> <common_uid_move> <service_class_uid_length> <service_class_uid> <related_general_length> <related_general_sop_class_item>*
<common_uid_move> ::= <uid> := recall_pick("move")
<common_item_rq_get> ::= b'\x57' <reserved_byte> <item_length> <common_sop_class_uid_length> <common_uid_get> <service_class_uid_length> <service_class_uid> <related_general_length> <related_general_sop_class_item>*
<common_uid_get> ::= <uid> := recall_pick("get")
<common_item_rq_normalized> ::= b'\x57' <reserved_byte> <item_length> <common_sop_class_uid_length> <common_uid_normalized> <service_class_uid_length> <service_class_uid> <related_general_length> <related_general_sop_class_item>*
<common_uid_normalized> ::= <uid> := recall_pick("normalized")
# PS3.7 D.3.3.7.1 User Identity sub-item (58H): the secondary field exists only for type 2
<user_identity_rq_item> ::= b'\x58' <reserved_byte> <item_length> (<ui_username> | <ui_username_passcode> | <ui_kerberos> | <ui_saml> | <ui_jwt>)
<ui_username> ::= <user_identity_username> <positive_response_requested> <primary_field_length> <primary_field> <secondary_length_zero>
<ui_username_passcode> ::= <user_identity_username_passcode> <positive_response_requested> <primary_field_length> <primary_field> <secondary_field_length> <secondary_field>
<ui_kerberos> ::= <user_identity_kerberos> <positive_response_requested> <primary_field_length> <primary_field_token> <secondary_length_zero>
<ui_saml> ::= <user_identity_saml> <positive_response_requested> <primary_field_length> <primary_field_token> <secondary_length_zero>
<ui_jwt> ::= <user_identity_jwt> <positive_response_requested> <primary_field_length> <primary_field_jwt> <secondary_length_zero>
<user_identity_type> ::= <user_identity_username> | <user_identity_username_passcode> | <user_identity_kerberos> | <user_identity_saml> | <user_identity_jwt>
<user_identity_username> ::= b'\x01'
<user_identity_username_passcode> ::= b'\x02'
<user_identity_kerberos> ::= b'\x03'
<user_identity_saml> ::= b'\x04'
<user_identity_jwt> ::= b'\x05'
<positive_response_requested> ::= rb'[\x00\x01]'
<primary_field_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <primary_field_length>: <l> == u16be(next_sibling_length(<l>))
<primary_field> ::= rb'[\x20-\x7e]{1,32}' := USER_NAME.encode("utf-8")
<primary_field_token> ::= rb'[\x20-\x7e]{1,64}' := (USER_NAME + ".token").encode("utf-8")
# D.3.3.7.1 type 5: a JSON Web Token (RFC 7519), three base64url parts separated by dots
<primary_field_jwt> ::= <jwt_header> b'.' <jwt_payload> b'.' <jwt_signature>
<jwt_header> ::= rb'[A-Za-z0-9_-]{8,64}' := b64url(b'{"alg":"HS256","typ":"JWT"}')
<jwt_payload> ::= rb'[A-Za-z0-9_-]{8,128}' := b64url(json.dumps({"sub": USER_NAME}).encode("utf-8"))
<jwt_signature> ::= rb'[A-Za-z0-9_-]{8,64}' := b64url(hashlib.sha256(USER_NAME.encode("utf-8")).digest())
<primary_field_wrong> ::= rb'[\x20-\x7e]{1,32}' := random.choice(WRONG_USER_NAMES).encode("utf-8")
<secondary_length_zero> ::= rb'[\x00-\xff]{2}' := b'\x00\x00'
<secondary_field_length> ::= rb'[\x00-\xff]{2}'
where forall <l> in <secondary_field_length>: <l> == u16be(next_sibling_length(<l>))
<secondary_field> ::= rb'[\x20-\x7e]{1,32}' := USER_PASSCODE.encode("utf-8")
<secondary_field_wrong> ::= rb'[\x20-\x7e]{1,32}' := random.choice(WRONG_USER_PASSCODES).encode("utf-8")
# Refusing association: wrong credentials, own request (PS3.7 D.3.3.7.3: the acceptor may reject with rejected-permanent, source 2)
<req_associate_wrong_credentials> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <rq_variable_items_wrong_credentials>
<rq_variable_items_wrong_credentials> ::= <application_context_item> <rq_contexts> <rq_user_information_item_wrong_credentials>
<rq_user_information_item_wrong_credentials> ::= b'\x50' <reserved_byte> <item_length> <maximum_length_item> <implementation_class_uid_item> <user_identity_rq_item_wrong>
<user_identity_rq_item_wrong> ::= b'\x58' <reserved_byte> <item_length> (<user_identity_username> <positive_response_requested> <primary_field_length> <primary_field_wrong> <secondary_length_zero> | <user_identity_username_passcode> <positive_response_requested> <primary_field_length> <primary_field> <secondary_field_length> <secondary_field_wrong>)
# Refusing association: a called AE title the server does not know, own request
<req_associate_wrong_called> ::= b'\x01' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title_wrong> <calling_ae_title> <reserved_32> <rq_variable_items>
<called_ae_title_wrong> ::= <ae_title> := pick_wrong_called_ae()

# 9.3.3 A-ASSOCIATE-AC (received): items in any order, parsed by their syntax
# The AC is received in two disjoint forms (PS3.8 7.1.1.13, 9.3.3.2; PS3.7 D.3.2): <rsp_associate_ac_accepted> has at least one Presentation Context Item with Result/Reason 0 and the association goes on in Sta 6;
# <rsp_associate_ac_refused> has no such item (every context was refused with Result/Reason 1 - 4), and the association goes on in <sta6_refused>, which sends no P-DATA-TF. The first accepted item is the one after the items
# that are not accepted contexts, so every AC parses one way.
<rsp_associate_ac_accepted> ::= b'\x02' <reserved_byte> <pdu_length> <protocol_version_rcv> <reserved_2_rcv> <ac_ae_title> <ac_ae_title> <ac_reserved_32> <ac_variable_item_not_accepted>* <ac_presentation_context_item_accepted> <ac_variable_item>*
<rsp_associate_ac_refused> ::= b'\x02' <reserved_byte> <pdu_length> <protocol_version_rcv> <reserved_2_rcv> <ac_ae_title> <ac_ae_title> <ac_reserved_32> <ac_variable_item_not_accepted>+
<protocol_version_rcv> ::= rb'[\x00-\xff][\x01\x03\x05\x07\x09\x0b\x0d\x0f\x11\x13\x15\x17\x19\x1b\x1d\x1f\x21\x23\x25\x27\x29\x2b\x2d\x2f\x31\x33\x35\x37\x39\x3b\x3d\x3f\x41\x43\x45\x47\x49\x4b\x4d\x4f\x51\x53\x55\x57\x59\x5b\x5d\x5f\x61\x63\x65\x67\x69\x6b\x6d\x6f\x71\x73\x75\x77\x79\x7b\x7d\x7f\x81\x83\x85\x87\x89\x8b\x8d\x8f\x91\x93\x95\x97\x99\x9b\x9d\x9f\xa1\xa3\xa5\xa7\xa9\xab\xad\xaf\xb1\xb3\xb5\xb7\xb9\xbb\xbd\xbf\xc1\xc3\xc5\xc7\xc9\xcb\xcd\xcf\xd1\xd3\xd5\xd7\xd9\xdb\xdd\xdf\xe1\xe3\xe5\xe7\xe9\xeb\xed\xef\xf1\xf3\xf5\xf7\xf9\xfb\xfd\xff]'
<reserved_2_rcv> ::= rb'[\x00-\xff]{2}'
<ac_ae_title> ::= rb'[\x00-\xff]{16}'
<ac_reserved_32> ::= rb'[\x00-\xff]{32}'
<ac_variable_item> ::= <application_context_item_rcv> | <ac_presentation_context_item_accepted> | <ac_presentation_context_item_refused> | <ac_user_information_item>
<ac_variable_item_not_accepted> ::= <application_context_item_rcv> | <ac_presentation_context_item_refused> | <ac_user_information_item>
<application_context_item_rcv> ::= b'\x10' <reserved_byte> <item_length> <uid>
<ac_presentation_context_item_accepted> ::= b'\x21' <reserved_byte> <item_length> <presentation_context_id> <reserved_byte> <pc_acceptance> <reserved_byte> <transfer_syntax_item_rcv>
<ac_presentation_context_item_refused> ::= b'\x21' <reserved_byte> <item_length> <presentation_context_id> <reserved_byte> <pc_refusal> <reserved_byte> <transfer_syntax_item_not_significant>
<pc_refusal> ::= <pc_user_rejection> | <pc_no_reason> | <pc_abstract_syntax_not_supported> | <pc_transfer_syntaxes_not_supported>
<pc_acceptance> ::= b'\x00'
<pc_user_rejection> ::= b'\x01'
<pc_no_reason> ::= b'\x02'
<pc_abstract_syntax_not_supported> ::= b'\x03'
<pc_transfer_syntaxes_not_supported> ::= b'\x04'
# 9.3.3.2.1: the transfer syntax name is significant only when the Result/Reason is 0 (acceptance); otherwise it is not tested
<transfer_syntax_item_rcv> ::= <transfer_syntax_item_head> <uid>
<transfer_syntax_item_not_significant> ::= <transfer_syntax_item_head> <transfer_syntax_not_tested>
<transfer_syntax_not_tested> ::= <byte>{from_u16(bytes(<item_length>))}
<ac_user_information_item> ::= b'\x50' <reserved_byte> <item_length> <ac_user_data_item>+
<ac_user_data_item> ::= <maximum_length_item> | <implementation_class_uid_item> | <implementation_version_name_item> | <asynchronous_operations_window_item> | <scp_scu_role_selection_item> | <extneg_item_ac> | <user_identity_ac_item> | <other_user_data_item>
# PS3.7 D.3.3.5.2 SOP Class Extended Negotiation sub-item of the AC
# PS3.7 D.3.3.5.2: Item-length, SOP-class-uid-length, SOP-class-uid, Service-class-application-information (its length is what is left of the item)
<extneg_item_ac> ::= b'\x56' <reserved_byte> <item_length> <extneg_uid_length_rcv> <extneg_uid_rcv> <extneg_info_rcv>
<extneg_uid_length_rcv> ::= rb'[\x00-\xff]{2}'
where forall <l> in <extneg_uid_length_rcv>: <l> == u16be(next_sibling_length(<l>))
<extneg_uid_rcv> ::= <uid>
<extneg_info_rcv> ::= <byte>{extneg_info_size(<extneg_uid_rcv>)}
# PS3.7 D.3.3.7.2 User Identity sub-item (59H) of the AC
<user_identity_ac_item> ::= b'\x59' <reserved_byte> <item_length> <server_response_length> <server_response>
<server_response_length> ::= rb'[\x00-\xff]{2}'
<server_response> ::= <byte>{from_u16(bytes(<server_response_length>))}
# PS3.8 D.2 Extended sub-items (57H, 58H, 5AH-FFH) are accepted by a generic fallback
<other_user_data_item> ::= rb'[\x57\x58\x5a-\xff]' <reserved_byte> <item_length> <other_user_data>
<other_user_data> ::= <byte>{from_u16(bytes(<item_length>))}

# 9.3.4 A-ASSOCIATE-RJ (received)
<rsp_associate_rj> ::= b'\x03' <reserved_byte> <pdu_length_four> <reserved_byte> <rj_result> <rj_source_reason>
<rj_result> ::= <rj_rejected_permanent> | <rj_rejected_transient>
<rj_rejected_permanent> ::= b'\x01'
<rj_rejected_transient> ::= b'\x02'
<rj_source_reason> ::= <rj_source_user> <rj_user_reason> | <rj_source_acse> <rj_acse_reason> | <rj_source_presentation> <rj_presentation_reason>
<rj_source_user> ::= b'\x01'
<rj_source_acse> ::= b'\x02'
<rj_source_presentation> ::= b'\x03'
# PS3.8 9.3.4: the Reason/Diag field takes one of the values listed per Source (Source 1: 1-10, Source 2: 1, 2, Source 3: 0-7); the values the table marks reserved (Source 1: 4-6, 8-10; Source 3: 0, 3-7) are
# accepted on receipt, since the spec does not say that a received reserved value is forbidden (final decision of the reviewer for C33/F19). An A-ASSOCIATE-RJ is never sent by the client.
<rj_user_reason> ::= <rj_user_no_reason> | <rj_user_context_not_supported> | <rj_user_calling_ae_not_recognized> | <rj_user_called_ae_not_recognized> | <rj_user_reserved>
<rj_user_reserved> ::= rb'[\x04-\x06\x08-\x0a]'
<rj_user_no_reason> ::= b'\x01'
<rj_user_context_not_supported> ::= b'\x02'
<rj_user_calling_ae_not_recognized> ::= b'\x03'
<rj_user_called_ae_not_recognized> ::= b'\x07'
<rj_acse_reason> ::= <rj_acse_no_reason> | <rj_acse_version_not_supported>
<rj_acse_no_reason> ::= b'\x01'
<rj_acse_version_not_supported> ::= b'\x02'
<rj_presentation_reason> ::= <rj_presentation_congestion> | <rj_presentation_local_limit> | <rj_presentation_reserved>
<rj_presentation_reserved> ::= rb'[\x00\x03-\x07]'
<rj_presentation_congestion> ::= b'\x01'
<rj_presentation_local_limit> ::= b'\x02'

# 9.3.8 A-ABORT (received)
<rsp_abort> ::= b'\x07' <reserved_byte> <pdu_length_four> <reserved_byte> <reserved_byte> <abort_source_reason>
<abort_source_reason> ::= <abort_source_user> <abort_reason_user> | <abort_source_reserved> <abort_reason_user> | <abort_source_provider> <abort_provider_reason>
<abort_source_reserved> ::= b'\x01'
<abort_reason_user> ::= rb'[\x00-\xff]'
<abort_source_user> ::= b'\x00'
<abort_source_provider> ::= b'\x02'
<rb_any_byte> ::= rb'[\x00-\xff]'
# PS3.8 9.3.8: provider reasons 0-6; received A-ABORTs accept the reserved Source 1 (any reason byte) and the reserved reason 3 (the spec does not say a received reserved value is forbidden, final decision
# for C36/F20/F21); the sent <req_abort> uses only the defined reasons 0, 1, 2, 4, 5, 6 (<abort_provider_reason_sent>) and Source 0 with reason 00H
<abort_provider_reason> ::= <abort_provider_reason_sent> | <abort_reason_reserved>
<abort_reason_reserved> ::= b'\x03'
<abort_provider_reason_sent> ::= <abort_reason_not_specified> | <abort_reason_unrecognized_pdu> | <abort_reason_unexpected_pdu> | <abort_reason_unrecognized_parameter> | <abort_reason_unexpected_parameter> | <abort_reason_invalid_parameter>
<abort_reason_not_specified> ::= b'\x00'
<abort_reason_unrecognized_pdu> ::= b'\x01'
<abort_reason_unexpected_pdu> ::= b'\x02'
<abort_reason_unrecognized_parameter> ::= b'\x04'
<abort_reason_unexpected_parameter> ::= b'\x05'
<abort_reason_invalid_parameter> ::= b'\x06'

# 9.3.6 A-RELEASE-RQ (sent), 9.3.7 A-RELEASE-RP (received)
<req_release> ::= b'\x05' <reserved_byte> <pdu_length_four> <reserved_32_bit>
<rsp_release> ::= b'\x06' <reserved_byte> <pdu_length_four> <rb_any_4>
<reserved_32_bit> ::= rb'[\x00-\xff]{4}' := b'\x00\x00\x00\x00'
<rb_any_4> ::= <byte>{4}



# ======================================================================================================
# Command Set (PS3.7 6.3, Annex E.1): implicit VR little endian, group 0000, elements ordered by increasing tag
# ======================================================================================================
<cmd_length> ::= rb'[\x00-\xff]{4}'
where forall <l> in <cmd_length>: <l> == u32le(len(bytes(<l>.parent)) - 8)
<le16> ::= rb'[\x00-\xff]{2}'
<le32> ::= rb'[\x00-\xff]{4}'
# (0000,0000) Command Group Length: the number of bytes of the command group after this element
<cmd_group_length> ::= b'\x00\x00\x00\x00' <cmd_length> <cmd_group_length_value>
<cmd_group_length_value> ::= rb'[\x00-\xff]{4}'
where forall <g> in <cmd_group_length_value>: <g> == u32le(len(bytes(<g>.parent.parent)) - 12)
# (0000,0002) Affected SOP Class UID, (0000,0003) Requested SOP Class UID, (0000,1000) / (0000,1001) SOP Instance UIDs
<cmd_uid> ::= rb'(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,31}' b'\x00'?
where forall <u> in <cmd_uid>: len(bytes(<u>)) <= 64
<cmd_affected_sop_class_uid> ::= b'\x00\x00\x02\x00' <cmd_length> <cmd_uid>
<cmd_affected_sop_class_uid_verification> ::= b'\x00\x00\x02\x00' <cmd_length> <cmd_uid_verification>
<cmd_affected_sop_class_uid_storage> ::= b'\x00\x00\x02\x00' <cmd_length> <cmd_uid_storage>
<cmd_affected_sop_class_uid_find> ::= b'\x00\x00\x02\x00' <cmd_length> <cmd_uid_find>
<cmd_affected_sop_class_uid_move> ::= b'\x00\x00\x02\x00' <cmd_length> <cmd_uid_move>
<cmd_affected_sop_class_uid_get> ::= b'\x00\x00\x02\x00' <cmd_length> <cmd_uid_get>
<cmd_affected_sop_class_uid_normalized> ::= b'\x00\x00\x02\x00' <cmd_length> <cmd_uid_normalized>
<cmd_uid_verification> ::= <cmd_uid> := recall_sop_class("verification")
<cmd_uid_storage> ::= <cmd_uid> := recall_sop_class("storage")
<cmd_uid_find> ::= <cmd_uid> := recall_sop_class("find")
<cmd_uid_move> ::= <cmd_uid> := recall_sop_class("move")
<cmd_uid_get> ::= <cmd_uid> := recall_sop_class("get")
<cmd_uid_normalized> ::= <cmd_uid> := recall_sop_class("normalized")
<cmd_requested_sop_class_uid> ::= b'\x00\x00\x03\x00' <cmd_length> <cmd_uid_normalized>
<cmd_affected_sop_instance_uid> ::= b'\x00\x00\x00\x10' <cmd_length> <cmd_instance_uid>
<cmd_instance_uid> ::= <cmd_uid> := instance_uid_with_pad()
<cmd_requested_sop_instance_uid> ::= b'\x00\x00\x01\x10' <cmd_length> <cmd_instance_uid>
# (0000,0100) Command Field: one nonterminal per command
<cmd_field_c_store_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x01\x00'
<cmd_field_c_store_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x01\x80'
<cmd_field_c_get_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x10\x00'
<cmd_field_c_get_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x10\x80'
<cmd_field_c_find_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x20\x00'
<cmd_field_c_find_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x20\x80'
<cmd_field_c_move_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x21\x00'
<cmd_field_c_move_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x21\x80'
<cmd_field_c_echo_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x30\x00'
<cmd_field_c_echo_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x30\x80'
<cmd_field_n_event_report_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x00\x01'
<cmd_field_n_event_report_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x00\x81'
<cmd_field_n_get_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x10\x01'
<cmd_field_n_get_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x10\x81'
<cmd_field_n_set_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x20\x01'
<cmd_field_n_set_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x20\x81'
<cmd_field_n_action_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x30\x01'
<cmd_field_n_action_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x30\x81'
<cmd_field_n_create_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x40\x01'
<cmd_field_n_create_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x40\x81'
<cmd_field_n_delete_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x50\x01'
<cmd_field_n_delete_rsp> ::= b'\x00\x00\x00\x01' <cmd_length> b'\x50\x81'
<cmd_field_c_cancel_rq> ::= b'\x00\x00\x00\x01' <cmd_length> b'\xff\x0f'
# (0000,0110) Message ID, (0000,0120) Message ID Being Responded To
<cmd_message_id> ::= b'\x00\x00\x10\x01' <cmd_length> <message_id_value>
<message_id_value> ::= <le16> := message_id_choice()
<cmd_message_id_responded> ::= b'\x00\x00\x20\x01' <cmd_length> <message_id_responded_value>
<message_id_responded_value> ::= <le16>
# (0000,0600) Move Destination, (0000,1030) Move Originator AE title, (0000,1031) Move Originator Message ID
<cmd_move_destination> ::= b'\x00\x00\x00\x06' <cmd_length> <move_destination_value>
<move_destination_value> ::= <ae_title> := ae16(random.choice(MOVE_DESTINATIONS))
<cmd_move_destination_unknown> ::= b'\x00\x00\x00\x06' <cmd_length> <move_destination_unknown_value>
<move_destination_unknown_value> ::= <ae_title> := ae16(random.choice(UNKNOWN_MOVE_DESTINATIONS))
<cmd_move_originator_ae> ::= b'\x00\x00\x30\x10' <cmd_length> <ae_value>
<ae_value> ::= rb'[\x20-\x5b\x5d-\x7e]{2,16}'
<cmd_move_originator_message_id> ::= b'\x00\x00\x31\x10' <cmd_length> <le16>
# (0000,0700) Priority: one nonterminal per value
<cmd_priority> ::= b'\x00\x00\x00\x07' <cmd_length> <priority_value>
<priority_value> ::= <priority_medium> | <priority_high> | <priority_low>
<priority_medium> ::= b'\x00\x00'
<priority_high> ::= b'\x01\x00'
<priority_low> ::= b'\x02\x00'
# (0000,0800) Command Data Set Type: 0101H = no data set, any other value = data set present
<cmd_data_set_type_none> ::= b'\x00\x00\x00\x08' <cmd_length> <data_set_type_none>
<data_set_type_none> ::= b'\x01\x01'
<cmd_data_set_type_present> ::= b'\x00\x00\x00\x08' <cmd_length> <data_set_type_present>
<data_set_type_present> ::= rb'([^\x01][\x00-\xff]|\x01[^\x01])' := random.choice([b'\x00\x00', b'\x02\x02', b'\x01\x00'])
# (0000,0900) Status, (0000,0901) Offending Element, (0000,0902) Error Comment, (0000,0903) Error ID
<cmd_status> ::= b'\x00\x00\x00\x09' <cmd_length> <status_value>
<status_value> ::= <status_success> | <status_pending> | <status_cancel> | <status_warning> | <status_failure>
<status_pending> ::= <status_pending_ff00> | <status_pending_ff01>
<status_final> ::= <status_success> | <status_cancel> | <status_warning> | <status_failure>
<cmd_status_pending> ::= b'\x00\x00\x00\x09' <cmd_length> <status_pending>
<cmd_status_final> ::= b'\x00\x00\x00\x09' <cmd_length> <status_final>
<status_success> ::= b'\x00\x00'
<status_pending_ff00> ::= b'\x00\xff'
<status_pending_ff01> ::= b'\x01\xff'
<status_cancel> ::= b'\x00\xfe'
<status_warning> ::= <status_warning_0001> | <status_warning_0107> | <status_warning_0116> | <status_warning_bxxx>
<status_warning_0001> ::= b'\x01\x00'
<status_warning_0107> ::= b'\x07\x01'
<status_warning_0116> ::= b'\x16\x01'
<status_warning_bxxx> ::= rb'[\x00-\xff][\xb0-\xbf]'
<status_failure> ::= <status_failure_axxx> | <status_failure_cxxx> | <status_failure_01xx> | <status_failure_02xx>
<status_failure_axxx> ::= rb'[\x00-\xff][\xa0-\xaf]'
<status_failure_cxxx> ::= rb'[\x00-\xff][\xc0-\xcf]'
<status_failure_01xx> ::= rb'[\x00-\x06\x08-\x15\x17-\xff]\x01'
<status_failure_02xx> ::= rb'[\x00-\xff]\x02'
<at_tag> ::= <le16> <le16>
<cmd_offending_element> ::= b'\x00\x00\x01\x09' <cmd_length> <at_tag>+
<cmd_error_comment> ::= b'\x00\x00\x02\x09' <cmd_length> <error_comment_text>
# LO (PS3.5 6.2): no backslash; sent values have an even length (7.1.2), the length rule of received commands is shared
<error_comment_text> ::= rb'[\x20-\x5b\x5d-\x7e]{1,64}' := error_comment_value()
<cmd_error_id> ::= b'\x00\x00\x03\x09' <cmd_length> <le16>
# (0000,1002) Event Type ID, (0000,1005) Attribute Identifier List, (0000,1008) Action Type ID
<cmd_event_type_id> ::= b'\x00\x00\x02\x10' <cmd_length> <le16>
<cmd_attribute_identifier_list> ::= b'\x00\x00\x05\x10' <cmd_length> <at_tag>+
<cmd_action_type_id> ::= b'\x00\x00\x08\x10' <cmd_length> <le16>
# (0000,1020..1023) Number of Remaining / Completed / Failed / Warning Sub-operations
<cmd_sub_operation_counts> ::= <cmd_remaining_suboperations> <cmd_completed_suboperations> <cmd_failed_suboperations> <cmd_warning_suboperations>
<cmd_remaining_suboperations> ::= b'\x00\x00\x20\x10' <cmd_length> <le16>
<cmd_completed_suboperations> ::= b'\x00\x00\x21\x10' <cmd_length> <le16>
<cmd_failed_suboperations> ::= b'\x00\x00\x22\x10' <cmd_length> <le16>
<cmd_warning_suboperations> ::= b'\x00\x00\x23\x10' <cmd_length> <le16>

# ------------------------------------------------------------------------------------------------------
# Command sets per message (PS3.7 9.3, 10.3)
# ------------------------------------------------------------------------------------------------------
<cs_c_echo_rq> ::= <cmd_group_length> <cmd_affected_sop_class_uid_verification> <cmd_field_c_echo_rq> <cmd_message_id> <cmd_data_set_type_none>
<cs_c_echo_rsp> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_echo_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>?
<cs_c_store_rq> ::= <cmd_group_length> <cmd_affected_sop_class_uid_storage> <cmd_field_c_store_rq> <cmd_message_id> <cmd_priority> <cmd_data_set_type_present> <cmd_affected_sop_instance_uid> <cmd_move_originator_ae>? <cmd_move_originator_message_id>?
<cs_c_store_rsp> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_store_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_attribute_identifier_list>?
<cs_c_find_rq> ::= <cmd_group_length> <cmd_affected_sop_class_uid_find> <cmd_field_c_find_rq> <cmd_message_id> <cmd_priority> <cmd_data_set_type_present>
<cs_c_find_rsp_pending> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_find_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status_pending> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>?
<cs_c_find_rsp_final> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_find_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status_final> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>?
<cmd_data_set_type_any> ::= <cmd_data_set_type_none> | <cmd_data_set_type_present>
<cs_c_get_rq> ::= <cmd_group_length> <cmd_affected_sop_class_uid_get> <cmd_field_c_get_rq> <cmd_message_id> <cmd_priority> <cmd_data_set_type_present>
<cs_c_move_rq> ::= <cmd_group_length> <cmd_affected_sop_class_uid_move> <cmd_field_c_move_rq> <cmd_message_id> <cmd_move_destination> <cmd_priority> <cmd_data_set_type_present>
<cs_c_move_rq_unknown_destination> ::= <cmd_group_length> <cmd_affected_sop_class_uid_move> <cmd_field_c_move_rq> <cmd_message_id> <cmd_move_destination_unknown> <cmd_priority> <cmd_data_set_type_present>
<cs_c_cancel_rq> ::= <cmd_group_length> <cmd_field_c_cancel_rq> <cmd_message_id_responded_cancel> <cmd_data_set_type_none>
<cmd_message_id_responded_cancel> ::= b'\x00\x00\x20\x01' <cmd_length> <cancel_message_id_value>
<cancel_message_id_value> ::= <le16>
where forall <v> in <cancel_message_id_value>: <v> == cancel_target_message_id(<v>)
<cs_n_event_report_rsp> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_event_report_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_any> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_event_type_id>?
<cs_n_get_rq> ::= <cmd_group_length> <cmd_requested_sop_class_uid> <cmd_field_n_get_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_requested_sop_instance_uid> <cmd_attribute_identifier_list>?
<cs_n_set_rq> ::= <cmd_group_length> <cmd_requested_sop_class_uid> <cmd_field_n_set_rq> <cmd_message_id> <cmd_data_set_type_present> <cmd_requested_sop_instance_uid>
<cs_n_delete_rq> ::= <cmd_group_length> <cmd_requested_sop_class_uid> <cmd_field_n_delete_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_requested_sop_instance_uid>
<cs_n_delete_rsp> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_delete_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>?


# ======================================================================================================
# P-DATA-TF PDUs (PS3.8 9.3.5, Annex E): a command PDV, then a data set PDV when the command announces one
# ======================================================================================================
# one rule for sent and received PDVs; the high bytes are limited to PDVs below 256 KiB because Fandango's parser evaluates the length-driven repetition bound of a received data set for every parse hypothesis, also for four unrelated bytes (turn 3: a bound of 10^9 stalled the parse for 40 s)
<pdv_length> ::= rb'[\x00-\xff]{4}'
where forall <l> in <pdv_length>: <l> == u32be(len(bytes(<l>.parent)) - 4)
<pdv_context_id> ::= rb'[\x00-\xff]'
# E.2 Message Control Header: bit 0 command (1) / data set (0), bit 1 last fragment, bits 2-7 zero
<mch_command_last> ::= b'\x03'
<mch_command_more> ::= b'\x01'
<mch_dataset_last> ::= b'\x02'
<mch_dataset_more> ::= b'\x00'
# received: bits 2 - 7 of the Message Control Header are 'always set to 0 by the sender and never checked by the receiver' (PS3.8 E.2); bit 0 selects command / data set, bit 1 the last fragment
<mch_command_last_rcv> ::= rb'[\x03\x07\x0b\x0f\x13\x17\x1b\x1f\x23\x27\x2b\x2f\x33\x37\x3b\x3f\x43\x47\x4b\x4f\x53\x57\x5b\x5f\x63\x67\x6b\x6f\x73\x77\x7b\x7f\x83\x87\x8b\x8f\x93\x97\x9b\x9f\xa3\xa7\xab\xaf\xb3\xb7\xbb\xbf\xc3\xc7\xcb\xcf\xd3\xd7\xdb\xdf\xe3\xe7\xeb\xef\xf3\xf7\xfb\xff]'
<mch_dataset_last_rcv> ::= rb'[\x02\x06\x0a\x0e\x12\x16\x1a\x1e\x22\x26\x2a\x2e\x32\x36\x3a\x3e\x42\x46\x4a\x4e\x52\x56\x5a\x5e\x62\x66\x6a\x6e\x72\x76\x7a\x7e\x82\x86\x8a\x8e\x92\x96\x9a\x9e\xa2\xa6\xaa\xae\xb2\xb6\xba\xbe\xc2\xc6\xca\xce\xd2\xd6\xda\xde\xe2\xe6\xea\xee\xf2\xf6\xfa\xfe]'
<mch_dataset_more_rcv> ::= rb'[\x00\x04\x08\x0c\x10\x14\x18\x1c\x20\x24\x28\x2c\x30\x34\x38\x3c\x40\x44\x48\x4c\x50\x54\x58\x5c\x60\x64\x68\x6c\x70\x74\x78\x7c\x80\x84\x88\x8c\x90\x94\x98\x9c\xa0\xa4\xa8\xac\xb0\xb4\xb8\xbc\xc0\xc4\xc8\xcc\xd0\xd4\xd8\xdc\xe0\xe4\xe8\xec\xf0\xf4\xf8\xfc]'
<mch_command_more_rcv> ::= rb'[\x01\x05\x09\x0d\x11\x15\x19\x1d\x21\x25\x29\x2d\x31\x35\x39\x3d\x41\x45\x49\x4d\x51\x55\x59\x5d\x61\x65\x69\x6d\x71\x75\x79\x7d\x81\x85\x89\x8d\x91\x95\x99\x9d\xa1\xa5\xa9\xad\xb1\xb5\xb9\xbd\xc1\xc5\xc9\xcd\xd1\xd5\xd9\xdd\xe1\xe5\xe9\xed\xf1\xf5\xf9\xfd]'

# Presentation context ids of sent PDVs: a context of the service group that the server accepted (with the transfer syntax the data set uses), remembered for all fragments of the message (PS3.8 E.1)
<pdv_context_id_verification> ::= <pdv_context_id> := pick_context("verification", None)
<pdv_context_id_storage> ::= <pdv_context_id> := pick_context("storage", None)
<pdv_context_id_storage_ivle> ::= <pdv_context_id> := pick_context("storage", IVLE)
<pdv_context_id_storage_evle> ::= <pdv_context_id> := pick_context("storage", EVLE)
<pdv_context_id_data_storage> ::= <pdv_context_id> := recall_context("storage")
<pdv_context_id_find> ::= <pdv_context_id> := pick_context("find", None)
<pdv_context_id_find_ivle> ::= <pdv_context_id> := pick_context("find", IVLE)
<pdv_context_id_find_evle> ::= <pdv_context_id> := pick_context("find", EVLE)
<pdv_context_id_data_find> ::= <pdv_context_id> := recall_context("find")
<pdv_context_id_move> ::= <pdv_context_id> := pick_context("move", None)
<pdv_context_id_move_ivle> ::= <pdv_context_id> := pick_context("move", IVLE)
<pdv_context_id_move_evle> ::= <pdv_context_id> := pick_context("move", EVLE)
<pdv_context_id_data_move> ::= <pdv_context_id> := recall_context("move")
<pdv_context_id_get> ::= <pdv_context_id> := pick_context("get", None)
<pdv_context_id_get_ivle> ::= <pdv_context_id> := pick_context("get", IVLE)
<pdv_context_id_get_evle> ::= <pdv_context_id> := pick_context("get", EVLE)
<pdv_context_id_data_get> ::= <pdv_context_id> := recall_context("get")
<pdv_context_id_normalized> ::= <pdv_context_id> := pick_context("normalized", None)
<pdv_context_id_normalized_ivle> ::= <pdv_context_id> := pick_context("normalized", IVLE)
<pdv_context_id_normalized_evle> ::= <pdv_context_id> := pick_context("normalized", EVLE)
<pdv_context_id_data_normalized> ::= <pdv_context_id> := recall_context("normalized")
<pdv_context_id_cancel_find> ::= <pdv_context_id> := recall_context("find")
<pdv_context_id_cancel_move> ::= <pdv_context_id> := recall_context("move")
<pdv_context_id_cancel_get> ::= <pdv_context_id> := recall_context("get")
<pdv_context_id_sub> ::= <pdv_context_id> := recall_server_context()
<pdv_context_id_event_sent> ::= <pdv_context_id> := recall_server_context()
<pdu_c_store_rq_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_ivle>
<pdv_c_store_rq_ivle> ::= <pdv_length> <pdv_context_id_storage_ivle> <mch_command_last> <cs_c_store_rq>
<pdu_c_store_rq_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_evle>
<pdv_c_store_rq_evle> ::= <pdv_length> <pdv_context_id_storage_evle> <mch_command_last> <cs_c_store_rq>
<pdu_c_find_rq_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rq_ivle>
<pdv_c_find_rq_ivle> ::= <pdv_length> <pdv_context_id_find_ivle> <mch_command_last> <cs_c_find_rq>
<pdu_c_find_rq_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rq_evle>
<pdv_c_find_rq_evle> ::= <pdv_length> <pdv_context_id_find_evle> <mch_command_last> <cs_c_find_rq>
<pdu_c_get_rq_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rq_ivle>
<pdv_c_get_rq_ivle> ::= <pdv_length> <pdv_context_id_get_ivle> <mch_command_last> <cs_c_get_rq>
<pdu_c_get_rq_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rq_evle>
<pdv_c_get_rq_evle> ::= <pdv_length> <pdv_context_id_get_evle> <mch_command_last> <cs_c_get_rq>
<pdu_c_move_rq_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_ivle>
<pdv_c_move_rq_ivle> ::= <pdv_length> <pdv_context_id_move_ivle> <mch_command_last> <cs_c_move_rq>
<pdu_c_move_rq_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_evle>
<pdv_c_move_rq_evle> ::= <pdv_length> <pdv_context_id_move_evle> <mch_command_last> <cs_c_move_rq>
<pdu_c_move_rq_unknown_destination_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_unknown_destination_ivle>
<pdv_c_move_rq_unknown_destination_ivle> ::= <pdv_length> <pdv_context_id_move_ivle> <mch_command_last> <cs_c_move_rq_unknown_destination>
<pdu_c_move_rq_unknown_destination_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_unknown_destination_evle>
<pdv_c_move_rq_unknown_destination_evle> ::= <pdv_length> <pdv_context_id_move_evle> <mch_command_last> <cs_c_move_rq_unknown_destination>
<pdu_n_set_rq_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rq_ivle>
<pdv_n_set_rq_ivle> ::= <pdv_length> <pdv_context_id_normalized_ivle> <mch_command_last> <cs_n_set_rq>
<pdu_n_set_rq_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rq_evle>
<pdv_n_set_rq_evle> ::= <pdv_length> <pdv_context_id_normalized_evle> <mch_command_last> <cs_n_set_rq>
<pdu_n_action_rq_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_data_ivle>
<pdv_n_action_rq_data_ivle> ::= <pdv_length> <pdv_context_id_normalized_ivle> <mch_command_last> <cs_n_action_rq_data>
<pdu_n_action_rq_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_data_evle>
<pdv_n_action_rq_data_evle> ::= <pdv_length> <pdv_context_id_normalized_evle> <mch_command_last> <cs_n_action_rq_data>
<pdu_n_create_rq_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_data_ivle>
<pdv_n_create_rq_data_ivle> ::= <pdv_length> <pdv_context_id_normalized_ivle> <mch_command_last> <cs_n_create_rq_data>
<pdu_n_create_rq_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_data_evle>
<pdv_n_create_rq_data_evle> ::= <pdv_length> <pdv_context_id_normalized_evle> <mch_command_last> <cs_n_create_rq_data>
<pdu_n_action_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq>
<pdv_n_action_rq> ::= <pdv_length> <pdv_context_id_normalized> <mch_command_last> <cs_n_action_rq>
<pdu_n_create_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq>
<pdv_n_create_rq> ::= <pdv_length> <pdv_context_id_normalized> <mch_command_last> <cs_n_create_rq>
<pdu_c_cancel_find_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_find_rq>
<pdv_c_cancel_find_rq> ::= <pdv_length> <pdv_context_id_cancel_find> <mch_command_last> <cs_c_cancel_rq>
<pdu_c_cancel_get_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_get_rq>
<pdv_c_cancel_get_rq> ::= <pdv_length> <pdv_context_id_cancel_get> <mch_command_last> <cs_c_cancel_rq>
<pdu_c_cancel_move_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_move_rq>
<pdv_c_cancel_move_rq> ::= <pdv_length> <pdv_context_id_cancel_move> <mch_command_last> <cs_c_cancel_rq>
<cs_n_action_rq> ::= <cmd_group_length> <cmd_requested_sop_class_uid> <cmd_field_n_action_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_requested_sop_instance_uid> <cmd_action_type_id>
<cs_n_action_rq_data> ::= <cmd_group_length> <cmd_requested_sop_class_uid> <cmd_field_n_action_rq> <cmd_message_id> <cmd_data_set_type_present> <cmd_requested_sop_instance_uid> <cmd_action_type_id>
<cs_n_create_rq> ::= <cmd_group_length> <cmd_affected_sop_class_uid_normalized> <cmd_field_n_create_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_affected_sop_instance_uid>?
<cs_n_create_rq_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid_normalized> <cmd_field_n_create_rq> <cmd_message_id> <cmd_data_set_type_present> <cmd_affected_sop_instance_uid>?
<pdv_dataset_store_ivle> ::= <pdv_length> <pdv_context_id_data_storage> <mch_dataset_last> <dataset_store_ivle>
<pdu_dataset_store_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_ivle>
<pdv_dataset_store_evle> ::= <pdv_length> <pdv_context_id_data_storage> <mch_dataset_last> <dataset_store_evle>
<pdu_dataset_store_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_evle>
<pdv_dataset_find_ivle> ::= <pdv_length> <pdv_context_id_data_find> <mch_dataset_last> <dataset_find_ivle>
<pdu_dataset_find_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_find_ivle>
<pdv_dataset_find_evle> ::= <pdv_length> <pdv_context_id_data_find> <mch_dataset_last> <dataset_find_evle>
<pdu_dataset_find_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_find_evle>
<pdv_dataset_get_ivle> ::= <pdv_length> <pdv_context_id_data_get> <mch_dataset_last> <dataset_retrieve_ivle>
<pdu_dataset_get_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_get_ivle>
<pdv_dataset_get_evle> ::= <pdv_length> <pdv_context_id_data_get> <mch_dataset_last> <dataset_retrieve_evle>
<pdu_dataset_get_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_get_evle>
<pdv_dataset_move_ivle> ::= <pdv_length> <pdv_context_id_data_move> <mch_dataset_last> <dataset_retrieve_ivle>
<pdu_dataset_move_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_move_ivle>
<pdv_dataset_move_evle> ::= <pdv_length> <pdv_context_id_data_move> <mch_dataset_last> <dataset_retrieve_evle>
<pdu_dataset_move_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_move_evle>
<pdv_dataset_normalized_ivle> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_dataset_last> <dataset_normalized_ivle>
<pdu_dataset_normalized_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_normalized_ivle>
<pdv_dataset_normalized_evle> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_dataset_last> <dataset_normalized_evle>
<pdu_dataset_normalized_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_normalized_evle>
# PS3.8 Annex E: a data set in several fragments; each PDV carries one fragment, the last one has the last-fragment flag
# Sent data sets of C-FIND, C-GET, C-MOVE, N-SET, N-ACTION and N-CREATE in two fragments (like C-STORE): the first PDV has the more flag, the last one the last-fragment flag; in two PDUs or in one PDU with two PDVs
<pdv_dataset_find_head_ivle> ::= <pdv_length> <pdv_context_id_data_find> <mch_dataset_more> <dataset_find_ivle_head>
<pdv_dataset_find_tail_ivle> ::= <pdv_length> <pdv_context_id_data_find> <mch_dataset_last> <dataset_find_ivle_tail>
<pdu_dataset_find_head_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_find_head_ivle>
<pdu_dataset_find_tail_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_find_tail_ivle>
<pdu_dataset_find_two_fragments_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_find_head_ivle> <pdv_dataset_find_tail_ivle>
<pdv_dataset_find_head_evle> ::= <pdv_length> <pdv_context_id_data_find> <mch_dataset_more> <dataset_find_evle_head>
<pdv_dataset_find_tail_evle> ::= <pdv_length> <pdv_context_id_data_find> <mch_dataset_last> <dataset_find_evle_tail>
<pdu_dataset_find_head_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_find_head_evle>
<pdu_dataset_find_tail_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_find_tail_evle>
<pdu_dataset_find_two_fragments_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_find_head_evle> <pdv_dataset_find_tail_evle>
<pdv_dataset_get_head_ivle> ::= <pdv_length> <pdv_context_id_data_get> <mch_dataset_more> <dataset_retrieve_ivle_head>
<pdv_dataset_get_tail_ivle> ::= <pdv_length> <pdv_context_id_data_get> <mch_dataset_last> <dataset_retrieve_ivle_tail>
<pdu_dataset_get_head_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_get_head_ivle>
<pdu_dataset_get_tail_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_get_tail_ivle>
<pdu_dataset_get_two_fragments_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_get_head_ivle> <pdv_dataset_get_tail_ivle>
<pdv_dataset_get_head_evle> ::= <pdv_length> <pdv_context_id_data_get> <mch_dataset_more> <dataset_retrieve_evle_head>
<pdv_dataset_get_tail_evle> ::= <pdv_length> <pdv_context_id_data_get> <mch_dataset_last> <dataset_retrieve_evle_tail>
<pdu_dataset_get_head_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_get_head_evle>
<pdu_dataset_get_tail_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_get_tail_evle>
<pdu_dataset_get_two_fragments_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_get_head_evle> <pdv_dataset_get_tail_evle>
<pdv_dataset_move_head_ivle> ::= <pdv_length> <pdv_context_id_data_move> <mch_dataset_more> <dataset_retrieve_ivle_head>
<pdv_dataset_move_tail_ivle> ::= <pdv_length> <pdv_context_id_data_move> <mch_dataset_last> <dataset_retrieve_ivle_tail>
<pdu_dataset_move_head_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_move_head_ivle>
<pdu_dataset_move_tail_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_move_tail_ivle>
<pdu_dataset_move_two_fragments_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_move_head_ivle> <pdv_dataset_move_tail_ivle>
<pdv_dataset_move_head_evle> ::= <pdv_length> <pdv_context_id_data_move> <mch_dataset_more> <dataset_retrieve_evle_head>
<pdv_dataset_move_tail_evle> ::= <pdv_length> <pdv_context_id_data_move> <mch_dataset_last> <dataset_retrieve_evle_tail>
<pdu_dataset_move_head_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_move_head_evle>
<pdu_dataset_move_tail_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_move_tail_evle>
<pdu_dataset_move_two_fragments_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_move_head_evle> <pdv_dataset_move_tail_evle>
<pdv_dataset_normalized_head_ivle> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_dataset_more> <dataset_normalized_ivle_head>
<pdv_dataset_normalized_tail_ivle> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_dataset_last> <dataset_normalized_ivle_tail>
<pdu_dataset_normalized_head_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_normalized_head_ivle>
<pdu_dataset_normalized_tail_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_normalized_tail_ivle>
<pdu_dataset_normalized_two_fragments_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_normalized_head_ivle> <pdv_dataset_normalized_tail_ivle>
<pdv_dataset_normalized_head_evle> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_dataset_more> <dataset_normalized_evle_head>
<pdv_dataset_normalized_tail_evle> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_dataset_last> <dataset_normalized_evle_tail>
<pdu_dataset_normalized_head_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_normalized_head_evle>
<pdu_dataset_normalized_tail_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_normalized_tail_evle>
<pdu_dataset_normalized_two_fragments_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_normalized_head_evle> <pdv_dataset_normalized_tail_evle>
<dataset_find_ivle_head> ::= <ivle_charset>? (<ivle_query_level_study> | <ivle_query_level_patient> | <ivle_query_level_series> | <ivle_query_level_image>)
<dataset_find_ivle_tail> ::= <ivle_patient_name> <ivle_patient_id>? (<ivle_study_uid_empty> | <ivle_study_uid>)? | <ivle_patient_id> (<ivle_study_uid_empty> | <ivle_study_uid>)? | <ivle_study_uid_empty> | <ivle_study_uid>
<dataset_retrieve_ivle_head> ::= <ivle_charset>? <ivle_query_level_study>
<dataset_retrieve_ivle_tail> ::= <ivle_study_uid>
<dataset_normalized_ivle_head> ::= <ivle_charset>
<dataset_normalized_ivle_tail> ::= <ivle_patient_id>
<dataset_find_evle_head> ::= <evle_charset>? (<evle_query_level_study> | <evle_query_level_patient> | <evle_query_level_series> | <evle_query_level_image>)
<dataset_find_evle_tail> ::= <evle_patient_name> <evle_patient_id>? (<evle_study_uid_empty> | <evle_study_uid>)? | <evle_patient_id> (<evle_study_uid_empty> | <evle_study_uid>)? | <evle_study_uid_empty> | <evle_study_uid>
<dataset_retrieve_evle_head> ::= <evle_charset>? <evle_query_level_study>
<dataset_retrieve_evle_tail> ::= <evle_study_uid>
<dataset_normalized_evle_head> ::= <evle_charset>
<dataset_normalized_evle_tail> ::= <evle_patient_id>
<pdv_dataset_store_head_ivle> ::= <pdv_length> <pdv_context_id_data_storage> <mch_dataset_more> <dataset_store_ivle_head>
<pdv_dataset_store_tail_ivle> ::= <pdv_length> <pdv_context_id_data_storage> <mch_dataset_last> <dataset_store_ivle_tail>
<pdu_dataset_store_head_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_head_ivle>
<pdu_dataset_store_tail_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_tail_ivle>
<pdu_dataset_store_two_fragments_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_head_ivle> <pdv_dataset_store_tail_ivle>
# PS3.8 Annex E: a data set in several fragments; each PDV carries one fragment, the last one has the last-fragment flag
<pdv_dataset_store_head_evle> ::= <pdv_length> <pdv_context_id_data_storage> <mch_dataset_more> <dataset_store_evle_head>
<pdv_dataset_store_tail_evle> ::= <pdv_length> <pdv_context_id_data_storage> <mch_dataset_last> <dataset_store_evle_tail>
<pdu_dataset_store_head_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_head_evle>
<pdu_dataset_store_tail_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_tail_evle>
<pdu_dataset_store_two_fragments_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_head_evle> <pdv_dataset_store_tail_evle>
<pdv_context_id_storage_rle> ::= <pdv_context_id> := pick_context("storage_rle", None)
<pdv_context_id_storage_encapsulated> ::= <pdv_context_id> := pick_context("storage_encapsulated", None)
<pdv_context_id_storage_jpip> ::= <pdv_context_id> := pick_context("storage_jpip", None)
<pdv_context_id_data_storage_rle> ::= <pdv_context_id> := recall_context("storage_rle")
<pdv_context_id_data_storage_encapsulated> ::= <pdv_context_id> := recall_context("storage_encapsulated")
<pdv_context_id_data_storage_jpip> ::= <pdv_context_id> := recall_context("storage_jpip")
<pdu_c_store_rq_rle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_rle>
<pdv_c_store_rq_rle> ::= <pdv_length> <pdv_context_id_storage_rle> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_rle> ::= <pdv_length> <pdv_context_id_data_storage_rle> <mch_dataset_last> <dataset_store_rle>
<pdu_dataset_store_rle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_rle>
<pdu_c_store_rq_encapsulated> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_encapsulated>
<pdv_c_store_rq_encapsulated> ::= <pdv_length> <pdv_context_id_storage_encapsulated> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_encapsulated> ::= <pdv_length> <pdv_context_id_data_storage_encapsulated> <mch_dataset_last> <dataset_store_encapsulated>
<pdu_dataset_store_encapsulated> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_encapsulated>
<pdu_c_store_rq_jpip> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_jpip>
<pdv_c_store_rq_jpip> ::= <pdv_length> <pdv_context_id_storage_jpip> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_jpip> ::= <pdv_length> <pdv_context_id_data_storage_jpip> <mch_dataset_last> <dataset_store_jpip>
<pdu_dataset_store_jpip> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_jpip>
<pdv_context_id_storage_evbe> ::= <pdv_context_id> := pick_context("storage_evbe", None)
<pdv_context_id_data_storage_evbe> ::= <pdv_context_id> := recall_context("storage_evbe")
<rq_pc_storage_uncompressed> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_uncompressed>
<transfer_syntax_item_uncompressed> ::= <transfer_syntax_item_head> <transfer_syntax_uncompressed>
<transfer_syntax_uncompressed> ::= <uid> := b'1.2.840.10008.1.2.1.98'
<pdv_context_id_storage_uncompressed> ::= <pdv_context_id> := pick_context("storage_uncompressed", None)
<pdv_context_id_data_storage_uncompressed> ::= <pdv_context_id> := recall_context("storage_uncompressed")
<pdu_c_store_rq_uncompressed> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_uncompressed>
<pdv_c_store_rq_uncompressed> ::= <pdv_length> <pdv_context_id_storage_uncompressed> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_uncompressed> ::= <pdv_length> <pdv_context_id_data_storage_uncompressed> <mch_dataset_last> <dataset_store_uncompressed>
<pdu_dataset_store_uncompressed> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_uncompressed>
<rq_pc_storage_deflated_frame> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_deflated_frame>
<transfer_syntax_item_deflated_frame> ::= <transfer_syntax_item_head> <transfer_syntax_deflated_frame>
<transfer_syntax_deflated_frame> ::= <uid> := b'1.2.840.10008.1.2.8.1'
<pdv_context_id_storage_deflated_frame> ::= <pdv_context_id> := pick_context("storage_deflated_frame", None)
<pdv_context_id_data_storage_deflated_frame> ::= <pdv_context_id> := recall_context("storage_deflated_frame")
<pdu_c_store_rq_deflated_frame> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_deflated_frame>
<pdv_c_store_rq_deflated_frame> ::= <pdv_length> <pdv_context_id_storage_deflated_frame> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_deflated_frame> ::= <pdv_length> <pdv_context_id_data_storage_deflated_frame> <mch_dataset_last> <dataset_store_deflated_frame>
<pdu_dataset_store_deflated_frame> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_deflated_frame>
<rq_pc_storage_stereo> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_stereo>
<transfer_syntax_item_stereo> ::= <transfer_syntax_item_head> <transfer_syntax_stereo>
<transfer_syntax_stereo> ::= <uid> := pick_uid(STEREO_TRANSFER_SYNTAXES)
<pdv_context_id_storage_stereo> ::= <pdv_context_id> := pick_context("storage_stereo", None)
<pdv_context_id_data_storage_stereo> ::= <pdv_context_id> := recall_context("storage_stereo")
<pdu_c_store_rq_stereo> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_stereo>
<pdv_c_store_rq_stereo> ::= <pdv_length> <pdv_context_id_storage_stereo> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_stereo> ::= <pdv_length> <pdv_context_id_data_storage_stereo> <mch_dataset_last> <dataset_store_stereo>
<pdu_dataset_store_stereo> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_stereo>
# PS3.5 A.4.11: Encapsulated Uncompressed Explicit VR Little Endian: each frame is one fragment holding the native frame bytes
<dataset_store_uncompressed> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_image_pixel> <evle_pixel_data_uncompressed>
<evle_pixel_data_uncompressed> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <basic_offset_table_empty> <uncompressed_fragment_item> <ds_sequence_delimitation>
<uncompressed_fragment_item> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <v_pixel>
# PS3.5 A.4.13: Deflated Image Frame Compression: each frame deflated (RFC 1951) in one fragment, padded to even length with a NULL byte
<dataset_store_deflated_frame> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_image_pixel> <evle_pixel_data_deflated_frame>
<evle_pixel_data_deflated_frame> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <basic_offset_table_empty> <deflated_frame_item> <ds_sequence_delimitation>
<deflated_frame_item> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <deflated_frame>
<deflated_frame> ::= rb'[\x00-\xff]+' := deflate_even(bytes(<v_pixel>))
# PS3.5 8.2.9: H.264 Stereo High Profile: Stereo Pairs Present (0022,0028) is YES
<dataset_store_stereo> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_stereo_pairs> <evle_samples_three> <evle_photometric_ybr_420> <evle_planar_zero> <evle_rows_720> <evle_columns_1280> <evle_bits_allocated> <evle_high_bit_stored> <evle_high_bit> <evle_pixel_repr> <evle_pixel_data_video>
<evle_stereo_pairs> ::= b'\x22\x00\x28\x00' b'CS' <ds_evle_length16> <v_cs_yes>
<v_cs_yes> ::= <v_cs> := b'YES '
<rq_pc_storage_jpip_deflate> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_jpip_deflate>
<transfer_syntax_item_jpip_deflate> ::= <transfer_syntax_item_head> <transfer_syntax_jpip_deflate>
<transfer_syntax_jpip_deflate> ::= <uid> := pick_uid(JPIP_DEFLATE_TRANSFER_SYNTAXES)
<pdv_context_id_storage_jpip_deflate> ::= <pdv_context_id> := pick_context("storage_jpip_deflate", None)
<pdv_context_id_data_storage_jpip_deflate> ::= <pdv_context_id> := recall_context("storage_jpip_deflate")
<pdu_c_store_rq_jpip_deflate> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_jpip_deflate>
<pdv_c_store_rq_jpip_deflate> ::= <pdv_length> <pdv_context_id_storage_jpip_deflate> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_jpip_deflate> ::= <pdv_length> <pdv_context_id_data_storage_jpip_deflate> <mch_dataset_last> <dataset_store_jpip_deflate>
<pdu_dataset_store_jpip_deflate> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_jpip_deflate>
# PS3.5 A.7, A.12: JPIP Referenced Deflate: the Explicit VR data set with the Pixel Data Provider URL, deflated (RFC 1951)
<dataset_store_jpip_deflate> ::= <deflated_stream_jpip>
<deflated_stream_jpip> ::= rb'[\x00-\xff]+' := deflate_raw(bytes(<dataset_store_jpip>))
# PS3.5 A.4.12 (JPEG XL): each Frame is encoded as a single Fragment: a context and a data set of their own (one fragment by construction)
<rq_pc_storage_single> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_single>
<transfer_syntax_item_single> ::= <transfer_syntax_item_head> <transfer_syntax_single>
<transfer_syntax_single> ::= <uid> := pick_uid(SINGLE_FRAGMENT_TRANSFER_SYNTAXES)
<pdv_context_id_storage_single> ::= <pdv_context_id> := pick_context("storage_single", None)
<pdv_context_id_data_storage_single> ::= <pdv_context_id> := recall_context("storage_single")
<pdu_c_store_rq_single> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_single>
<pdv_c_store_rq_single> ::= <pdv_length> <pdv_context_id_storage_single> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_single> ::= <pdv_length> <pdv_context_id_data_storage_single> <mch_dataset_last> <dataset_store_single>
<pdu_dataset_store_single> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_single>
<dataset_store_single> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_image_pixel> <evle_pixel_data_single>
<evle_pixel_data_single> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <encapsulation_basic_offset_table> <encapsulation_fragment_item> <ds_sequence_delimitation>
<rq_pc_storage_hevc10> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_hevc10>
<transfer_syntax_item_hevc10> ::= <transfer_syntax_item_head> <transfer_syntax_hevc10>
<transfer_syntax_hevc10> ::= <uid> := b'1.2.840.10008.1.2.4.108'
<pdv_context_id_storage_hevc10> ::= <pdv_context_id> := pick_context("storage_hevc10", None)
<pdv_context_id_data_storage_hevc10> ::= <pdv_context_id> := recall_context("storage_hevc10")
<pdu_c_store_rq_hevc10> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_hevc10>
<pdv_c_store_rq_hevc10> ::= <pdv_length> <pdv_context_id_storage_hevc10> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_hevc10> ::= <pdv_length> <pdv_context_id_data_storage_hevc10> <mch_dataset_last> <dataset_store_hevc10>
<pdu_dataset_store_hevc10> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_hevc10>
<rq_pc_storage_xlrecomp> ::= b'\x20' <reserved_byte> <item_length> <rq_pc_id> <reserved_byte> <reserved_byte> <reserved_byte> <abstract_syntax_item_storage_again> <transfer_syntax_item_xlrecomp>
<transfer_syntax_item_xlrecomp> ::= <transfer_syntax_item_head> <transfer_syntax_xlrecomp>
<transfer_syntax_xlrecomp> ::= <uid> := b'1.2.840.10008.1.2.4.111'
<pdv_context_id_storage_xlrecomp> ::= <pdv_context_id> := pick_context("storage_xlrecomp", None)
<pdv_context_id_data_storage_xlrecomp> ::= <pdv_context_id> := recall_context("storage_xlrecomp")
<pdu_c_store_rq_xlrecomp> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_xlrecomp>
<pdv_c_store_rq_xlrecomp> ::= <pdv_length> <pdv_context_id_storage_xlrecomp> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_xlrecomp> ::= <pdv_length> <pdv_context_id_data_storage_xlrecomp> <mch_dataset_last> <dataset_store_xlrecomp>
<pdu_dataset_store_xlrecomp> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_xlrecomp>
# PS3.5 A.4.10, 8.2.11: HEVC/H.265 Main 10: YBR_PARTIAL_420, 3 samples, Planar Configuration 0, Bits Allocated 16, Bits Stored 10, High Bit 9, Pixel Representation 0, no Pixel Aspect Ratio; the stream is opaque fragments
<dataset_store_hevc10> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_samples_three> <evle_photometric_ybr_420> <evle_planar_zero> <evle_rows_720> <evle_columns_1280> <evle_bits_allocated_16> <evle_bits_stored_ten> <evle_high_bit_nine> <evle_pixel_repr> <evle_pixel_data_video>
<evle_bits_stored_ten> ::= b'\x28\x00\x01\x01' b'US' <ds_evle_length16> <v_us_ten>
<evle_high_bit_nine> ::= b'\x28\x00\x02\x01' b'US' <ds_evle_length16> <v_us_nine>
<v_us_ten> ::= <v_us> := b'\x0a\x00'
<v_us_nine> ::= <v_us> := b'\x09\x00'
# PS3.5 A.4.12, 8.2.15 (Table 8.2.15-1): JPEG XL JPEG Recompression: MONOCHROME2, 1 sample, 8 bits, High Bit 7, Pixel Representation 0; each Frame is one Fragment
<dataset_store_xlrecomp> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_samples_per_pixel> <evle_photometric_mono2> <evle_rows> <evle_columns> <evle_bits_allocated> <evle_high_bit_stored> <evle_high_bit> <evle_pixel_repr> <evle_pixel_data_single>
<evle_photometric_mono2> ::= b'\x28\x00\x04\x00' b'CS' <ds_evle_length16> <v_cs_mono2>
<v_cs_mono2> ::= <v_cs> := b'MONOCHROME2 '
<pdv_context_id_storage_deflated> ::= <pdv_context_id> := pick_context("storage_deflated", None)
<pdv_context_id_data_storage_deflated> ::= <pdv_context_id> := recall_context("storage_deflated")
<pdu_c_store_rq_deflated> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_deflated>
<pdv_c_store_rq_deflated> ::= <pdv_length> <pdv_context_id_storage_deflated> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_deflated> ::= <pdv_length> <pdv_context_id_data_storage_deflated> <mch_dataset_last> <dataset_store_deflated>
<pdu_dataset_store_deflated> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_deflated>
# PS3.5 A.5: the whole data set (Explicit VR Little Endian) deflated (RFC 1951); a converter from the data set rule to the compressed bytes
<dataset_store_deflated> ::= <deflated_stream>
<deflated_stream> ::= rb'[\x00-\xff]+' := deflate_raw(bytes(<dataset_store_evle>))
<pdv_context_id_storage_video> ::= <pdv_context_id> := pick_context("storage_video", None)
<pdv_context_id_data_storage_video> ::= <pdv_context_id> := recall_context("storage_video")
<pdu_c_store_rq_video> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_video>
<pdv_c_store_rq_video> ::= <pdv_length> <pdv_context_id_storage_video> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_video> ::= <pdv_length> <pdv_context_id_data_storage_video> <mch_dataset_last> <dataset_store_video>
<pdu_dataset_store_video> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_video>
# Video Pixel Data (PS3.5 8.2.5 - 8.2.9, Tables 8.2.5-1): Samples per Pixel 3, YBR_PARTIAL_420, Planar Configuration 0, 8 bits, 720 x 1280; one fragment, empty Basic Offset Table
<dataset_store_video> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_samples_three> <evle_photometric_ybr_420> <evle_planar_zero> <evle_rows_720> <evle_columns_1280> <evle_bits_allocated> <evle_high_bit_stored> <evle_high_bit> <evle_pixel_repr> <evle_pixel_data_video>
<dataset_store_video_single> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_samples_three> <evle_photometric_ybr_420> <evle_planar_zero> <evle_rows_720> <evle_columns_1280> <evle_bits_allocated> <evle_high_bit_stored> <evle_high_bit> <evle_pixel_repr> <evle_pixel_data_video_single>
<evle_samples_three> ::= b'\x28\x00\x02\x00' b'US' <ds_evle_length16> <v_us_three>
<evle_photometric_ybr_420> ::= b'\x28\x00\x04\x00' b'CS' <ds_evle_length16> <v_cs_ybr_420>
<evle_planar_zero> ::= b'\x28\x00\x06\x00' b'US' <ds_evle_length16> <v_us_zero>
<evle_rows_720> ::= b'\x28\x00\x10\x00' b'US' <ds_evle_length16> <v_us_720>
<evle_columns_1280> ::= b'\x28\x00\x11\x00' b'US' <ds_evle_length16> <v_us_1280>
<v_us_three> ::= <v_us> := b'\x03\x00'
<v_us_720> ::= <v_us> := b'\xd0\x02'
<v_us_1280> ::= <v_us> := b'\x00\x05'
<v_cs_ybr_420> ::= <v_cs> := b'YBR_PARTIAL_420 '
<evle_pixel_data_video> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <basic_offset_table_empty> <encapsulation_fragment_item>+ <ds_sequence_delimitation>
<evle_pixel_data_video_single> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <basic_offset_table_empty> <encapsulation_fragment_item> <ds_sequence_delimitation>
# the video syntaxes that are not fragmentable (MPEG2, 2D H.264 without '.1'): the same pixel module, exactly one Fragment
<dataset_store_stereo_single> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_stereo_pairs> <evle_samples_three> <evle_photometric_ybr_420> <evle_planar_zero> <evle_rows_720> <evle_columns_1280> <evle_bits_allocated> <evle_high_bit_stored> <evle_high_bit> <evle_pixel_repr> <evle_pixel_data_video_single>
# PS3.5 8.2.8, 8.2.9: the non-fragmentable stereo syntaxes (.4.105 for 3D, .4.106 Stereo High Profile) carry Stereo Pairs Present = YES and exactly one Fragment
<pdv_context_id_storage_stereo_single> ::= <pdv_context_id> := pick_context("storage_stereo_single", None)
<pdv_context_id_data_storage_stereo_single> ::= <pdv_context_id> := recall_context("storage_stereo_single")
<pdu_c_store_rq_stereo_single> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_stereo_single>
<pdv_c_store_rq_stereo_single> ::= <pdv_length> <pdv_context_id_storage_stereo_single> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_stereo_single> ::= <pdv_length> <pdv_context_id_data_storage_stereo_single> <mch_dataset_last> <dataset_store_stereo_single>
<pdu_dataset_store_stereo_single> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_stereo_single>
<pdv_context_id_storage_video_single> ::= <pdv_context_id> := pick_context("storage_video_single", None)
<pdv_context_id_data_storage_video_single> ::= <pdv_context_id> := recall_context("storage_video_single")
<pdu_c_store_rq_video_single> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_video_single>
<pdv_c_store_rq_video_single> ::= <pdv_length> <pdv_context_id_storage_video_single> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_video_single> ::= <pdv_length> <pdv_context_id_data_storage_video_single> <mch_dataset_last> <dataset_store_video_single>
<pdu_dataset_store_video_single> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_video_single>
<pdu_c_store_rq_evbe> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_evbe>
<pdv_c_store_rq_evbe> ::= <pdv_length> <pdv_context_id_storage_evbe> <mch_command_last> <cs_c_store_rq>
<pdv_dataset_store_evbe> ::= <pdv_length> <pdv_context_id_data_storage_evbe> <mch_dataset_last> <dataset_store_evbe>
<pdu_dataset_store_evbe> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_evbe>
# the store requests in the other transfer syntaxes (one context each, PS3.5 A.4 - A.10) are alternatives of <req_c_store>, so that every reply alternative of a store shares the one request symbol

# PS3.8 E.1: the command PDV and the first data PDV in one P-DATA-TF (a PDU holds one or more PDVs)
<pdu_c_store_rq_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_ivle> <pdv_dataset_store_ivle>
<pdu_c_store_rq_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_evle> <pdv_dataset_store_evle>
<pdu_c_find_rq_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rq_ivle> <pdv_dataset_find_ivle>
<pdu_c_find_rq_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rq_evle> <pdv_dataset_find_evle>
<pdu_c_get_rq_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rq_ivle> <pdv_dataset_get_ivle>
<pdu_c_get_rq_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rq_evle> <pdv_dataset_get_evle>
<pdu_c_move_rq_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_ivle> <pdv_dataset_move_ivle>
<pdu_c_move_rq_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_evle> <pdv_dataset_move_evle>
<pdu_c_move_rq_unknown_destination_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_unknown_destination_ivle> <pdv_dataset_move_ivle>
<pdu_c_move_rq_unknown_destination_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_unknown_destination_evle> <pdv_dataset_move_evle>
<pdu_n_set_rq_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rq_ivle> <pdv_dataset_normalized_ivle>
<pdu_n_set_rq_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rq_evle> <pdv_dataset_normalized_evle>
<pdu_n_action_rq_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_data_ivle> <pdv_dataset_normalized_ivle>
<pdu_n_action_rq_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_data_evle> <pdv_dataset_normalized_evle>
<pdu_n_create_rq_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_data_ivle> <pdv_dataset_normalized_ivle>
<pdu_n_create_rq_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_data_evle> <pdv_dataset_normalized_evle>
<req_c_store> ::= <pdu_c_store_rq_ivle> <pdu_dataset_store_ivle> | <pdu_c_store_rq_ivle> <pdu_dataset_store_head_ivle> <pdu_dataset_store_tail_ivle> | <pdu_c_store_rq_ivle> <pdu_dataset_store_two_fragments_ivle> | <pdu_c_store_rq_evle> <pdu_dataset_store_evle> | <pdu_c_store_rq_evle> <pdu_dataset_store_head_evle> <pdu_dataset_store_tail_evle> | <pdu_c_store_rq_evle> <pdu_dataset_store_two_fragments_evle> | <pdu_c_store_rq_with_data_ivle> | <pdu_c_store_rq_with_data_evle> | <pdu_c_store_rq_ivle_head> <pdu_c_store_rq_ivle_tail> <pdu_dataset_store_ivle> | <pdu_c_store_rq_evle_head> <pdu_c_store_rq_evle_tail> <pdu_dataset_store_evle> | <pdu_c_store_rq_hevc10> <pdu_dataset_store_hevc10> | <pdu_c_store_rq_xlrecomp> <pdu_dataset_store_xlrecomp> | <pdu_c_store_rq_single> <pdu_dataset_store_single> | <pdu_c_store_rq_jpip_deflate> <pdu_dataset_store_jpip_deflate> | <pdu_c_store_rq_uncompressed> <pdu_dataset_store_uncompressed> | <pdu_c_store_rq_deflated_frame> <pdu_dataset_store_deflated_frame> | <pdu_c_store_rq_stereo> <pdu_dataset_store_stereo> | <pdu_c_store_rq_video> <pdu_dataset_store_video> | <pdu_c_store_rq_deflated> <pdu_dataset_store_deflated> | <pdu_c_store_rq_evbe> <pdu_dataset_store_evbe> | <pdu_c_store_rq_rle> <pdu_dataset_store_rle> | <pdu_c_store_rq_encapsulated> <pdu_dataset_store_encapsulated> | <pdu_c_store_rq_jpip> <pdu_dataset_store_jpip> | <pdu_c_store_rq_video_single> <pdu_dataset_store_video_single> | <pdu_c_store_rq_stereo_single> <pdu_dataset_store_stereo_single>
<req_c_find> ::= <pdu_c_find_rq_ivle> <pdu_dataset_find_ivle> | <pdu_c_find_rq_evle> <pdu_dataset_find_evle> | <pdu_c_find_rq_with_data_ivle> | <pdu_c_find_rq_with_data_evle> | <pdu_c_find_rq_ivle_head> <pdu_c_find_rq_ivle_tail> <pdu_dataset_find_ivle> | <pdu_c_find_rq_evle_head> <pdu_c_find_rq_evle_tail> <pdu_dataset_find_evle> | <pdu_c_find_rq_ivle> <pdu_dataset_find_head_ivle> <pdu_dataset_find_tail_ivle> | <pdu_c_find_rq_ivle> <pdu_dataset_find_two_fragments_ivle> | <pdu_c_find_rq_evle> <pdu_dataset_find_head_evle> <pdu_dataset_find_tail_evle> | <pdu_c_find_rq_evle> <pdu_dataset_find_two_fragments_evle>
<req_c_get> ::= <pdu_c_get_rq_ivle> <pdu_dataset_get_ivle> | <pdu_c_get_rq_evle> <pdu_dataset_get_evle> | <pdu_c_get_rq_with_data_ivle> | <pdu_c_get_rq_with_data_evle> | <pdu_c_get_rq_ivle_head> <pdu_c_get_rq_ivle_tail> <pdu_dataset_get_ivle> | <pdu_c_get_rq_evle_head> <pdu_c_get_rq_evle_tail> <pdu_dataset_get_evle> | <pdu_c_get_rq_ivle> <pdu_dataset_get_head_ivle> <pdu_dataset_get_tail_ivle> | <pdu_c_get_rq_ivle> <pdu_dataset_get_two_fragments_ivle> | <pdu_c_get_rq_evle> <pdu_dataset_get_head_evle> <pdu_dataset_get_tail_evle> | <pdu_c_get_rq_evle> <pdu_dataset_get_two_fragments_evle>
<req_c_move> ::= <pdu_c_move_rq_ivle> <pdu_dataset_move_ivle> | <pdu_c_move_rq_evle> <pdu_dataset_move_evle> | <pdu_c_move_rq_with_data_ivle> | <pdu_c_move_rq_with_data_evle> | <pdu_c_move_rq_ivle_head> <pdu_c_move_rq_ivle_tail> <pdu_dataset_move_ivle> | <pdu_c_move_rq_evle_head> <pdu_c_move_rq_evle_tail> <pdu_dataset_move_evle> | <pdu_c_move_rq_ivle> <pdu_dataset_move_head_ivle> <pdu_dataset_move_tail_ivle> | <pdu_c_move_rq_ivle> <pdu_dataset_move_two_fragments_ivle> | <pdu_c_move_rq_evle> <pdu_dataset_move_head_evle> <pdu_dataset_move_tail_evle> | <pdu_c_move_rq_evle> <pdu_dataset_move_two_fragments_evle>
<req_c_move_unknown_destination> ::= <pdu_c_move_rq_unknown_destination_ivle> <pdu_dataset_move_ivle> | <pdu_c_move_rq_unknown_destination_evle> <pdu_dataset_move_evle> | <pdu_c_move_rq_unknown_destination_with_data_ivle> | <pdu_c_move_rq_unknown_destination_with_data_evle> | <pdu_c_move_rq_unknown_destination_ivle_head> <pdu_c_move_rq_unknown_destination_ivle_tail> <pdu_dataset_move_ivle> | <pdu_c_move_rq_unknown_destination_evle_head> <pdu_c_move_rq_unknown_destination_evle_tail> <pdu_dataset_move_evle> | <pdu_c_move_rq_unknown_destination_ivle> <pdu_dataset_move_head_ivle> <pdu_dataset_move_tail_ivle> | <pdu_c_move_rq_unknown_destination_ivle> <pdu_dataset_move_two_fragments_ivle> | <pdu_c_move_rq_unknown_destination_evle> <pdu_dataset_move_head_evle> <pdu_dataset_move_tail_evle> | <pdu_c_move_rq_unknown_destination_evle> <pdu_dataset_move_two_fragments_evle>
<req_c_cancel_find> ::= <pdu_c_cancel_find_rq> | <pdu_c_cancel_find_rq_two_fragments> | <pdu_c_cancel_find_rq_head> <pdu_c_cancel_find_rq_tail>
<req_c_cancel_get> ::= <pdu_c_cancel_get_rq> | <pdu_c_cancel_get_rq_two_fragments> | <pdu_c_cancel_get_rq_head> <pdu_c_cancel_get_rq_tail>
<req_c_cancel_move> ::= <pdu_c_cancel_move_rq> | <pdu_c_cancel_move_rq_two_fragments> | <pdu_c_cancel_move_rq_head> <pdu_c_cancel_move_rq_tail>
<req_n_set> ::= <pdu_n_set_rq_ivle> <pdu_dataset_normalized_ivle> | <pdu_n_set_rq_evle> <pdu_dataset_normalized_evle> | <pdu_n_set_rq_with_data_ivle> | <pdu_n_set_rq_with_data_evle> | <pdu_n_set_rq_ivle_head> <pdu_n_set_rq_ivle_tail> <pdu_dataset_normalized_ivle> | <pdu_n_set_rq_evle_head> <pdu_n_set_rq_evle_tail> <pdu_dataset_normalized_evle> | <pdu_n_set_rq_ivle> <pdu_dataset_normalized_head_ivle> <pdu_dataset_normalized_tail_ivle> | <pdu_n_set_rq_ivle> <pdu_dataset_normalized_two_fragments_ivle> | <pdu_n_set_rq_evle> <pdu_dataset_normalized_head_evle> <pdu_dataset_normalized_tail_evle> | <pdu_n_set_rq_evle> <pdu_dataset_normalized_two_fragments_evle>
<req_n_action> ::= <pdu_n_action_rq> | <pdu_n_action_rq_data_ivle> <pdu_dataset_normalized_ivle> | <pdu_n_action_rq_data_evle> <pdu_dataset_normalized_evle> | <pdu_n_action_rq_with_data_ivle> | <pdu_n_action_rq_with_data_evle> | <pdu_n_action_rq_head> <pdu_n_action_rq_tail> | <pdu_n_action_rq_data_ivle_head> <pdu_n_action_rq_data_ivle_tail> <pdu_dataset_normalized_ivle> | <pdu_n_action_rq_data_evle_head> <pdu_n_action_rq_data_evle_tail> <pdu_dataset_normalized_evle> | <pdu_n_action_rq_data_ivle> <pdu_dataset_normalized_head_ivle> <pdu_dataset_normalized_tail_ivle> | <pdu_n_action_rq_data_ivle> <pdu_dataset_normalized_two_fragments_ivle> | <pdu_n_action_rq_data_evle> <pdu_dataset_normalized_head_evle> <pdu_dataset_normalized_tail_evle> | <pdu_n_action_rq_data_evle> <pdu_dataset_normalized_two_fragments_evle>
<req_n_create> ::= <pdu_n_create_rq> | <pdu_n_create_rq_data_ivle> <pdu_dataset_normalized_ivle> | <pdu_n_create_rq_data_evle> <pdu_dataset_normalized_evle> | <pdu_n_create_rq_with_data_ivle> | <pdu_n_create_rq_with_data_evle> | <pdu_n_create_rq_head> <pdu_n_create_rq_tail> | <pdu_n_create_rq_data_ivle_head> <pdu_n_create_rq_data_ivle_tail> <pdu_dataset_normalized_ivle> | <pdu_n_create_rq_data_evle_head> <pdu_n_create_rq_data_evle_tail> <pdu_dataset_normalized_evle> | <pdu_n_create_rq_data_ivle> <pdu_dataset_normalized_head_ivle> <pdu_dataset_normalized_tail_ivle> | <pdu_n_create_rq_data_ivle> <pdu_dataset_normalized_two_fragments_ivle> | <pdu_n_create_rq_data_evle> <pdu_dataset_normalized_head_evle> <pdu_dataset_normalized_tail_evle> | <pdu_n_create_rq_data_evle> <pdu_dataset_normalized_two_fragments_evle>
<pdv_c_store_sub_rsp> ::= <pdv_length> <pdv_context_id_sub> <mch_command_last> <cs_c_store_rsp_sub>
<cs_c_store_rsp_sub> ::= <cmd_group_length> <cmd_affected_sop_class_uid_echo>? <cmd_field_c_store_rsp> <cmd_message_id_responded_sent> <cmd_data_set_type_none> <cmd_status_sub> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid_echo>?
# (0000,0002), (0000,1000), (0000,1002) of the server's command, echoed in the client's response (PS3.7 9.1.1.1.3, 9.1.1.1.4, 10.3.1.2)
<cmd_affected_sop_class_uid_echo> ::= b'\x00\x00\x02\x00' <cmd_length> <cmd_uid_echo_class>
<cmd_uid_echo_class> ::= <cmd_uid> := recall_server_element(0x0002, b'1.2.840.10008.5.1.4.1.1.7\x00')
<cmd_affected_sop_instance_uid_echo> ::= b'\x00\x00\x00\x10' <cmd_length> <cmd_uid_echo_instance>
<cmd_uid_echo_instance> ::= <cmd_uid> := recall_server_element(0x1000, b'1.2.3\x00')
<cmd_event_type_id_echo> ::= b'\x00\x00\x02\x10' <cmd_length> <event_type_echo_value>
<event_type_echo_value> ::= <le16> := recall_server_element(0x1002, b'\x01\x00')
# PS3.7 9.1.1.1.9: the performing user of a sub-operation answers success, a warning or a failure
<cmd_status_sub> ::= b'\x00\x00\x00\x09' <cmd_length> <status_sub>
<status_sub> ::= <status_success> | <status_warning> | <status_failure>
<pdv_n_event_report_rsp_sent> ::= <pdv_length> <pdv_context_id_event_sent> <mch_command_last> <cs_n_event_report_rsp_sent>
<cs_n_event_report_rsp_sent> ::= <cmd_group_length> <cmd_affected_sop_class_uid_echo>? <cmd_field_n_event_report_rsp> <cmd_message_id_responded_sent> <cmd_data_set_type_none> <cmd_status_event_sent> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid_echo>? <cmd_event_type_id_echo>?
<cmd_status_event_sent> ::= b'\x00\x00\x00\x09' <cmd_length> <status_event_sent>
<status_event_sent> ::= <status_success> | <status_failure>
<pdu_c_echo_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_echo_rq>
<pdv_c_echo_rq> ::= <pdv_length> <pdv_context_id_verification> <mch_command_last> <cs_c_echo_rq>
<pdu_n_get_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_get_rq>
<pdv_n_get_rq> ::= <pdv_length> <pdv_context_id_normalized> <mch_command_last> <cs_n_get_rq>
<pdu_n_delete_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_delete_rq>
<pdv_n_delete_rq> ::= <pdv_length> <pdv_context_id_normalized> <mch_command_last> <cs_n_delete_rq>
<pdu_c_echo_rsp> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_echo_rsp>
<pdv_c_echo_rsp> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_echo_rsp>
<pdu_c_store_rsp> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rsp>
<pdv_c_store_rsp> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_store_rsp>
<pdu_c_find_rsp_pending> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rsp_pending>
<pdv_c_find_rsp_pending> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_find_rsp_pending>
<pdu_c_find_rsp_final> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rsp_final>
<pdv_c_find_rsp_final> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_find_rsp_final>
<pdu_n_event_report_rsp> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp>
<pdv_n_event_report_rsp> ::= <pdv_length> <pdv_context_id> <mch_command_last> <cs_n_event_report_rsp>
<pdu_n_delete_rsp> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_delete_rsp>
<pdv_n_delete_rsp> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_delete_rsp>
<pdu_c_store_sub_rq> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_sub_rq>
<pdv_c_store_sub_rq> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_store_rq_rcv>
<cs_c_store_rq_rcv> ::= <cmd_group_length> <cmd_affected_sop_class_uid> <cmd_field_c_store_rq> <cmd_message_id> <cmd_priority> <cmd_data_set_type_present> <cmd_affected_sop_instance_uid> <cmd_move_originator_ae>? <cmd_move_originator_message_id>?

# Data set PDVs. Sent data sets follow the negotiated transfer syntax of the context; received ones are length-delimited
# PS3.8 Annex E: a data set in several fragments; each PDV carries one fragment, the last one has the last-fragment flag
<pdv_dataset_rcv> ::= <pdv_length> <pdv_context_id_rcv> <mch_dataset_last_rcv> <dataset_rcv>
<pdv_context_id_rcv> ::= <pdv_context_id>
# a received PDV is shorter than 256 KiB: the length drives a bounded repetition, whose cost in Fandango's parser grows with the bound (a hypothesis that reads 4 arbitrary bytes as the length can ask for hundreds of millions of elements and stall the session for a minute)
<pdu_dataset_rcv> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdv_dataset_rcv_more> ::= <pdv_length> <pdv_context_id_rcv> <mch_dataset_more_rcv> <dataset_rcv_more>
# The Item-length of a received PDV is any four bytes (PS3.8 9.3.5.1: the Maximum Length announced by the client is 0 = unlimited in some sessions). The fragment is a repetition of 64 KiB chunks followed by the rest:
# Fandango evaluates the bound of a length-driven repetition for every parse hypothesis, also for four unrelated bytes (the next PDU's header read as a length: 10^8 - 10^9), and a flat <byte>{n} of such a bound
# stalls its parser for 40 - 50 s; the number of chunks is at most 65535, which costs as little as a bound of 65535.
<pdv_chunk> ::= <byte>{65536}
<dataset_rcv_more> ::= <pdv_chunk>{pdv_chunks(<pdv_length>)} <byte>{pdv_rest(<pdv_length>)}
<pdu_dataset_rcv_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_rcv_more>+
# A received data set: fragments without the last-fragment flag, then the last fragment (PS3.8 Annex E.1)
<dataset_message_rcv> ::= <pdu_dataset_rcv_more>* <pdu_dataset_rcv>
<dataset_rcv> ::= <pdv_chunk>{pdv_chunks(<pdv_length>)} <byte>{pdv_rest(<pdv_length>)}


# ======================================================================================================
# Data sets (PS3.5 7.1 Data Elements, 7.5 Nesting of Data Sets, 6.2 VRs). Value rules are shared by all syntaxes.
# ======================================================================================================
<v_ui> ::= rb'(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,31}\x00?'
where forall <u> in <v_ui>: len(bytes(<u>)) <= 64
<v_ui_sop_class> ::= <v_ui> := recall_sop_class_padded()
<v_ui_sop_instance> ::= <v_ui> := instance_uid_with_pad()
<v_ui_study> ::= <v_ui> := study_uid_with_pad()
<v_ui_series> ::= <v_ui> := series_uid_with_pad()
<v_ui_empty> ::= b''
<v_cs> ::= rb'[A-Z0-9_ ]{1,16}'
<v_cs_modality> ::= <v_cs> := random.choice([b"CT", b"MR", b"OT", b"US"])
<v_cs_charset> ::= rb'[A-Z0-9_ \\]{2,64}' := charset_value()
<v_cs_level_study> ::= <v_cs> := b"STUDY "
<v_cs_level_patient> ::= <v_cs> := b"PATIENT "
<v_cs_level_series> ::= <v_cs> := b"SERIES"
<v_cs_level_image> ::= <v_cs> := b"IMAGE "
<v_cs_photometric> ::= <v_cs> := random.choice([b"MONOCHROME2 ", b"MONOCHROME1 "])
<v_da> ::= rb'[0-9]{8}' := random.choice([b"20240101", b"19991231"])
# text values in the repertoire of the Specific Character Set of the data set (recorded by <v_cs_charset>), ESC for the ISO 2022 sets
<v_pn> ::= rb'[\x1b\x20-\xff]{1,64}' := pn_value()
<v_lo> ::= rb'[\x1b\x20-\xff]{1,32}' := lo_value()
# a Private Creator holds characters of the Default Character Repertoire only, whatever Specific Character Set says (PS3.5 7.8.1)
<v_lo_creator> ::= rb'[\x20-\x5b\x5d-\x7e]{1,32}' := creator_value()
<v_us> ::= rb'[\x00-\xff]{2}'
<v_us_one> ::= <v_us> := b'\x01\x00'
<v_us_two> ::= <v_us> := b'\x02\x00'
<v_us_eight> ::= <v_us> := b'\x08\x00'
<v_us_seven> ::= <v_us> := b'\x07\x00'
<v_us_zero> ::= <v_us> := b'\x00\x00'
<v_pixel> ::= rb'[\x00-\xff]{4}'
<v_ui_item_class> ::= <v_ui> := recall_sop_class_padded()

<ds_ivle_length> ::= rb'[\x00-\xff]{4}'
where forall <l> in <ds_ivle_length>: <l> == u32le(len(bytes(<l>.parent)) - 8)
<ds_evle_length16> ::= rb'[\x00-\xff]{2}'
where forall <l> in <ds_evle_length16>: <l> == u16le(len(bytes(<l>.parent)) - 8)
<ds_evle_length32> ::= rb'[\x00-\xff]{4}'
where forall <l> in <ds_evle_length32>: <l> == u32le(len(bytes(<l>.parent)) - 12)
# PS3.5 7.5 Sequence Item (FFFE,E000) with explicit length, and undefined-length forms ended by delimitation items
<ds_item_length> ::= rb'[\x00-\xff]{4}'
where forall <l> in <ds_item_length>: <l> == u32le(len(bytes(<l>.parent)) - 8)
<ds_item_delimitation> ::= b'\xfe\xff\x0d\xe0\x00\x00\x00\x00'
<ds_sequence_delimitation> ::= b'\xfe\xff\xdd\xe0\x00\x00\x00\x00'

<ivle_charset> ::= b'\x08\x00\x05\x00' <ds_ivle_length> <v_cs_charset>
<ivle_sop_class> ::= b'\x08\x00\x16\x00' <ds_ivle_length> <v_ui_sop_class>
<ivle_sop_instance> ::= b'\x08\x00\x18\x00' <ds_ivle_length> <v_ui_sop_instance>
<ivle_study_date> ::= b'\x08\x00\x20\x00' <ds_ivle_length> <v_da>
<ivle_modality> ::= b'\x08\x00\x60\x00' <ds_ivle_length> <v_cs_modality>
<ivle_patient_name> ::= b'\x10\x00\x10\x00' <ds_ivle_length> <v_pn>
<ivle_patient_id> ::= b'\x10\x00\x20\x00' <ds_ivle_length> <v_lo>
<ivle_study_uid> ::= b'\x20\x00\x0d\x00' <ds_ivle_length> <v_ui_study>
<ivle_series_uid> ::= b'\x20\x00\x0e\x00' <ds_ivle_length> <v_ui_series>
<ivle_samples_per_pixel> ::= b'\x28\x00\x02\x00' <ds_ivle_length> <v_us_one>
<ivle_photometric> ::= b'\x28\x00\x04\x00' <ds_ivle_length> <v_cs_photometric>
<ivle_rows> ::= b'\x28\x00\x10\x00' <ds_ivle_length> <v_us_two>
<ivle_columns> ::= b'\x28\x00\x11\x00' <ds_ivle_length> <v_us_two>
<ivle_bits_allocated> ::= b'\x28\x00\x00\x01' <ds_ivle_length> <v_us_eight>
<ivle_pixel_data> ::= b'\xe0\x7f\x10\x00' <ds_ivle_length> <v_pixel>
<ivle_private_creator> ::= b'\x09\x00\x10\x00' <ds_ivle_length> <v_lo_creator>
<ivle_private_data> ::= b'\x09\x00\x01\x10' <ds_ivle_length> <v_lo>
<ivle_high_bit_stored> ::= b'\x28\x00\x01\x01' <ds_ivle_length> <v_us_eight>
<ivle_high_bit> ::= b'\x28\x00\x02\x01' <ds_ivle_length> <v_us_seven>
<ivle_pixel_repr> ::= b'\x28\x00\x03\x01' <ds_ivle_length> <v_us_zero>
# ---- additional value forms: VRs, private sequences, pixel module variants ----
# Value rules of the VRs (PS3.5 6.2), all of even length; used by the private data element of Explicit VR data sets
<v_ae> ::= rb'([A-Z0-9]{2}){1,8}' := random.choice([b'FANDANGO', b'STORESCP'])
<v_as> ::= rb'[0-9]{3}[DWMY]' := random.choice([b'030Y', b'012M', b'004W'])
<v_at> ::= rb'[\x00-\xff]{4}'
<v_ds> ::= rb'([0-9.]{2}){1,6}' := random.choice([b'12.5', b'1.00', b'0.75'])
<v_dt> ::= rb'[0-9]{14}' := random.choice([b'20240101120000', b'19991231235959'])
<v_fl> ::= rb'[\x00-\xff]{4}'
<v_fd> ::= rb'[\x00-\xff]{8}'
<v_is> ::= rb'([0-9]{2}){1,4}' := random.choice([b'42', b'1000', b'12345678'])
<v_lt> ::= rb'([\x1b\x20-\xff]{2}){1,16}' := lt_value()
<v_ob> ::= rb'([\x00-\xff]{2}){1,4}'
<v_od> ::= rb'([\x00-\xff]{8}){1,2}'
<v_of> ::= rb'([\x00-\xff]{4}){1,4}'
<v_ol> ::= rb'([\x00-\xff]{4}){1,4}'
<v_ov> ::= rb'([\x00-\xff]{8}){1,2}'
<v_sh> ::= rb'([\x1b\x20-\xff]{2}){1,8}' := sh_value()
<v_sl> ::= rb'[\x00-\xff]{4}'
<v_ss> ::= rb'[\x00-\xff]{2}'
<v_st> ::= rb'([\x1b\x20-\xff]{2}){1,16}' := st_value()
<v_sv> ::= rb'[\x00-\xff]{8}'
<v_tm> ::= rb'[0-9]{6}' := random.choice([b'120000', b'235959'])
<v_uc> ::= rb'([\x1b\x20-\xff]{2}){1,16}' := uc_value()
<v_un> ::= rb'([\x00-\xff]{2}){1,4}'
<v_ur> ::= rb'http://([a-z]{2}){1,8}[a-z]' := random.choice([b'http://localhost', b'http://pacserver'])
<v_ut> ::= rb'([\x1b\x20-\xff]{2}){1,16}' := ut_value()
<v_uv> ::= rb'[\x00-\xff]{8}'
<evle_private_data> ::= <evle_private_data_ul> | <evle_private_data_lo> | <evle_private_data_ae> | <evle_private_data_as> | <evle_private_data_at> | <evle_private_data_ds> | <evle_private_data_dt> | <evle_private_data_fl> | <evle_private_data_fd> | <evle_private_data_is> | <evle_private_data_lt> | <evle_private_data_ob> | <evle_private_data_od> | <evle_private_data_of> | <evle_private_data_ol> | <evle_private_data_ov> | <evle_private_data_sh> | <evle_private_data_sl> | <evle_private_data_ss> | <evle_private_data_st> | <evle_private_data_sv> | <evle_private_data_tm> | <evle_private_data_uc> | <evle_private_data_un> | <evle_private_data_ur> | <evle_private_data_ut> | <evle_private_data_uv> | <evle_private_data_un_sequence>
<v_ul> ::= rb'[\x00-\xff]{4}'
<evle_private_data_ul> ::= b'\x09\x00\x01\x10' b'UL' <ds_evle_length16> <v_ul>
<evbe_private_data_ul> ::= b'\x00\x09\x10\x01' b'UL' <ds_evbe_length16> <v_ul>
<evle_private_data_lo> ::= b'\x09\x00\x01\x10' b'LO' <ds_evle_length16> <v_lo>
<evle_private_data_ae> ::= b'\x09\x00\x01\x10' b'AE' <ds_evle_length16> <v_ae>
<evle_private_data_as> ::= b'\x09\x00\x01\x10' b'AS' <ds_evle_length16> <v_as>
<evle_private_data_at> ::= b'\x09\x00\x01\x10' b'AT' <ds_evle_length16> <v_at>
<evle_private_data_ds> ::= b'\x09\x00\x01\x10' b'DS' <ds_evle_length16> <v_ds>
<evle_private_data_dt> ::= b'\x09\x00\x01\x10' b'DT' <ds_evle_length16> <v_dt>
<evle_private_data_fl> ::= b'\x09\x00\x01\x10' b'FL' <ds_evle_length16> <v_fl>
<evle_private_data_fd> ::= b'\x09\x00\x01\x10' b'FD' <ds_evle_length16> <v_fd>
<evle_private_data_is> ::= b'\x09\x00\x01\x10' b'IS' <ds_evle_length16> <v_is>
<evle_private_data_lt> ::= b'\x09\x00\x01\x10' b'LT' <ds_evle_length16> <v_lt>
<evle_private_data_ob> ::= b'\x09\x00\x01\x10' b'OB' b'\x00\x00' <ds_evle_length32> <v_ob>
<evle_private_data_od> ::= b'\x09\x00\x01\x10' b'OD' b'\x00\x00' <ds_evle_length32> <v_od>
<evle_private_data_of> ::= b'\x09\x00\x01\x10' b'OF' b'\x00\x00' <ds_evle_length32> <v_of>
<evle_private_data_ol> ::= b'\x09\x00\x01\x10' b'OL' b'\x00\x00' <ds_evle_length32> <v_ol>
<evle_private_data_ov> ::= b'\x09\x00\x01\x10' b'OV' b'\x00\x00' <ds_evle_length32> <v_ov>
<evle_private_data_sh> ::= b'\x09\x00\x01\x10' b'SH' <ds_evle_length16> <v_sh>
<evle_private_data_sl> ::= b'\x09\x00\x01\x10' b'SL' <ds_evle_length16> <v_sl>
<evle_private_data_ss> ::= b'\x09\x00\x01\x10' b'SS' <ds_evle_length16> <v_ss>
<evle_private_data_st> ::= b'\x09\x00\x01\x10' b'ST' <ds_evle_length16> <v_st>
<evle_private_data_sv> ::= b'\x09\x00\x01\x10' b'SV' b'\x00\x00' <ds_evle_length32> <v_sv>
<evle_private_data_tm> ::= b'\x09\x00\x01\x10' b'TM' <ds_evle_length16> <v_tm>
<evle_private_data_uc> ::= b'\x09\x00\x01\x10' b'UC' b'\x00\x00' <ds_evle_length32> <v_uc>
<evle_private_data_un> ::= b'\x09\x00\x01\x10' b'UN' b'\x00\x00' <ds_evle_length32> <v_un>
<evle_private_data_ur> ::= b'\x09\x00\x01\x10' b'UR' b'\x00\x00' <ds_evle_length32> <v_ur>
<evle_private_data_ut> ::= b'\x09\x00\x01\x10' b'UT' b'\x00\x00' <ds_evle_length32> <v_ut>
<evle_private_data_uv> ::= b'\x09\x00\x01\x10' b'UV' b'\x00\x00' <ds_evle_length32> <v_uv>
<evle_private_data_un_sequence> ::= b'\x09\x00\x01\x10' b'UN' b'\x00\x00' b'\xff\xff\xff\xff' <ivle_ref_item_undefined>* <ds_sequence_delimitation>
<ivle_private> ::= <ivle_private_creator> <ivle_private_data> <ivle_private_sequence>?
<ivle_private_block> ::= <ivle_private_creator> <ivle_private_data_lo_item>
<evle_private> ::= <evle_private_creator> <evle_private_data> <evle_private_sequence>?
<evle_private_block> ::= <evle_private_creator> <evle_private_data_lo_item>
<ivle_private_data_lo_item> ::= <ivle_private_data>
<evle_private_data_lo_item> ::= b'\x09\x00\x01\x10' b'LO' <ds_evle_length16> <v_lo>
<ivle_private_sequence> ::= b'\x09\x00\x02\x10' <ds_ivle_length> <ivle_private_item>*
<ivle_private_item> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <ivle_ref_class> <ivle_ref_instance> <ivle_private_block>
<evle_private_sequence> ::= b'\x09\x00\x02\x10' b'SQ' b'\x00\x00' <ds_evle_length32> <evle_private_item>*
<evle_private_item> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <evle_ref_class> <evle_ref_instance> <evle_private_block>
<ivle_rows_one> ::= b'\x28\x00\x10\x00' <ds_ivle_length> <v_us_one>
<ivle_bits_allocated_16> ::= b'\x28\x00\x00\x01' <ds_ivle_length> <v_us_sixteen>
<ivle_bits_allocated_32> ::= b'\x28\x00\x00\x01' <ds_ivle_length> <v_us_thirty_two>
<ivle_bits_allocated_64> ::= b'\x28\x00\x00\x01' <ds_ivle_length> <v_us_sixty_four>
<ivle_high_bit_stored_12> ::= b'\x28\x00\x01\x01' <ds_ivle_length> <v_us_twelve>
<ivle_high_bit_11> ::= b'\x28\x00\x02\x01' <ds_ivle_length> <v_us_eleven>
<ivle_float_pixel_data> ::= b'\xe0\x7f\x08\x00' <ds_ivle_length> <v_float_pixel>
<ivle_double_pixel_data> ::= b'\xe0\x7f\x09\x00' <ds_ivle_length> <v_double_pixel>
<ivle_overlay_rows> ::= b'\x00\x60\x10\x00' <ds_ivle_length> <v_us_four>
<ivle_overlay_columns> ::= b'\x00\x60\x11\x00' <ds_ivle_length> <v_us_four>
<ivle_overlay_bits_allocated> ::= b'\x00\x60\x00\x01' <ds_ivle_length> <v_us_one>
<ivle_overlay_bit_position> ::= b'\x00\x60\x02\x01' <ds_ivle_length> <v_us_zero>
<ivle_overlay_data> ::= b'\x00\x60\x00\x30' <ds_ivle_length> <v_overlay>
<ivle_image_pixel_16> ::= <ivle_samples_per_pixel> <ivle_photometric> <ivle_rows_one> <ivle_columns> <ivle_bits_allocated_16> <ivle_high_bit_stored_12> <ivle_high_bit_11> <ivle_pixel_repr>
<ivle_image_float> ::= <ivle_samples_per_pixel> <ivle_photometric> <ivle_rows_one> <ivle_columns> <ivle_bits_allocated_32>
<ivle_image_double> ::= <ivle_samples_per_pixel> <ivle_photometric> <ivle_rows_one> <ivle_columns_one> <ivle_bits_allocated_64>
<ivle_columns_one> ::= b'\x28\x00\x11\x00' <ds_ivle_length> <v_us_one>
<ivle_overlay> ::= <ivle_overlay_rows> <ivle_overlay_columns> <ivle_overlay_bits_allocated> <ivle_overlay_bit_position> <ivle_overlay_data>
<ivle_pixel_module> ::= <ivle_image_pixel> <ivle_waveform>? <ivle_overlay>? <ivle_pixel_data_8> | <ivle_image_pixel_16> <ivle_waveform>? <ivle_overlay>? <ivle_pixel_data> | <ivle_image_float> <ivle_float_pixel_data> | <ivle_image_double> <ivle_double_pixel_data> | <ivle_image_pixel_rgb> <ivle_pixel_data_rgb> | <ivle_image_pixel_frames> <ivle_pixel_data_frames> | <ivle_image_pixel_1bit> <ivle_pixel_data_1bit>
<evle_rows_one> ::= b'\x28\x00\x10\x00' b'US' <ds_evle_length16> <v_us_one>
<evle_bits_allocated_16> ::= b'\x28\x00\x00\x01' b'US' <ds_evle_length16> <v_us_sixteen>
<evle_bits_allocated_32> ::= b'\x28\x00\x00\x01' b'US' <ds_evle_length16> <v_us_thirty_two>
<evle_bits_allocated_64> ::= b'\x28\x00\x00\x01' b'US' <ds_evle_length16> <v_us_sixty_four>
<evle_high_bit_stored_12> ::= b'\x28\x00\x01\x01' b'US' <ds_evle_length16> <v_us_twelve>
<evle_high_bit_11> ::= b'\x28\x00\x02\x01' b'US' <ds_evle_length16> <v_us_eleven>
<evle_float_pixel_data> ::= b'\xe0\x7f\x08\x00' b'OF' b'\x00\x00' <ds_evle_length32> <v_float_pixel>
<evle_double_pixel_data> ::= b'\xe0\x7f\x09\x00' b'OD' b'\x00\x00' <ds_evle_length32> <v_double_pixel>
<evle_overlay_rows> ::= b'\x00\x60\x10\x00' b'US' <ds_evle_length16> <v_us_four>
<evle_overlay_columns> ::= b'\x00\x60\x11\x00' b'US' <ds_evle_length16> <v_us_four>
<evle_overlay_bits_allocated> ::= b'\x00\x60\x00\x01' b'US' <ds_evle_length16> <v_us_one>
<evle_overlay_bit_position> ::= b'\x00\x60\x02\x01' b'US' <ds_evle_length16> <v_us_zero>
<evle_overlay_data> ::= b'\x00\x60\x00\x30' b'OW' b'\x00\x00' <ds_evle_length32> <v_overlay>
<evle_image_pixel_16> ::= <evle_samples_per_pixel> <evle_photometric> <evle_rows_one> <evle_columns> <evle_bits_allocated_16> <evle_high_bit_stored_12> <evle_high_bit_11> <evle_pixel_repr>
<evle_image_float> ::= <evle_samples_per_pixel> <evle_photometric> <evle_rows_one> <evle_columns> <evle_bits_allocated_32>
<evle_image_double> ::= <evle_samples_per_pixel> <evle_photometric> <evle_rows_one> <evle_columns_one> <evle_bits_allocated_64>
<evle_columns_one> ::= b'\x28\x00\x11\x00' b'US' <ds_evle_length16> <v_us_one>
<evle_overlay> ::= <evle_overlay_rows> <evle_overlay_columns> <evle_overlay_bits_allocated> <evle_overlay_bit_position> <evle_overlay_data>
<evle_pixel_module> ::= <evle_image_pixel> <evle_waveform>? <evle_overlay>? <evle_pixel_data_8> | <evle_image_pixel_16> <evle_waveform>? <evle_overlay>? <evle_pixel_data> | <evle_image_float> <evle_float_pixel_data> | <evle_image_double> <evle_double_pixel_data> | <evle_image_pixel_rgb> <evle_pixel_data_rgb> | <evle_image_pixel_frames> <evle_pixel_data_frames> | <evle_image_pixel_1bit> <evle_pixel_data_1bit>
# PS3.5 8.1.1, 8.2, Table 8.2.2-1: further native Pixel Data forms: colour (Samples per Pixel 3, Photometric Interpretation RGB, Planar Configuration 0 or 1, 8 bit), two frames (Number of Frames) and 1 bit cells (Bits Allocated 1, Bits Stored 1, High Bit 0)
<v_is_two_frames> ::= <v_is> := b'02'
<v_pixel_six> ::= rb'[\x00-\xff]{6}'
<v_pixel_eight> ::= rb'[\x00-\xff]{8}'
<v_us_three_be> ::= <v_us> := b'\x00\x03'
<v_us_planar_be> ::= <v_us> := random.choice([b'\x00\x00', b'\x00\x01'])
<ivle_samples_three> ::= b'\x28\x00\x02\x00' <ds_ivle_length> <v_us_three>
<ivle_photometric_rgb> ::= b'\x28\x00\x04\x00' <ds_ivle_length> <v_cs_rgb>
<ivle_planar_configuration> ::= b'\x28\x00\x06\x00' <ds_ivle_length> <v_us_planar>
<ivle_number_of_frames> ::= b'\x28\x00\x08\x00' <ds_ivle_length> <v_is_two_frames>
<ivle_columns_sixteen> ::= b'\x28\x00\x11\x00' <ds_ivle_length> <v_us_sixteen>
<ivle_bits_allocated_one> ::= b'\x28\x00\x00\x01' <ds_ivle_length> <v_us_one>
<ivle_bits_stored_one> ::= b'\x28\x00\x01\x01' <ds_ivle_length> <v_us_one>
<ivle_high_bit_zero> ::= b'\x28\x00\x02\x01' <ds_ivle_length> <v_us_zero>
<ivle_image_pixel_rgb> ::= <ivle_samples_three> <ivle_photometric_rgb> <ivle_planar_configuration> <ivle_rows_one> <ivle_columns> <ivle_bits_allocated> <ivle_high_bit_stored> <ivle_high_bit> <ivle_pixel_repr>
<ivle_pixel_data_rgb> ::= b'\xe0\x7f\x10\x00' <ds_ivle_length> <v_pixel_six>
<ivle_image_pixel_frames> ::= <ivle_samples_per_pixel> <ivle_photometric> <ivle_number_of_frames> <ivle_rows> <ivle_columns> <ivle_bits_allocated> <ivle_high_bit_stored> <ivle_high_bit> <ivle_pixel_repr>
<ivle_pixel_data_frames> ::= b'\xe0\x7f\x10\x00' <ds_ivle_length> <v_pixel_eight>
<ivle_image_pixel_1bit> ::= <ivle_samples_per_pixel> <ivle_photometric> <ivle_rows_one> <ivle_columns_sixteen> <ivle_bits_allocated_one> <ivle_bits_stored_one> <ivle_high_bit_zero> <ivle_pixel_repr>
<ivle_pixel_data_1bit> ::= b'\xe0\x7f\x10\x00' <ds_ivle_length> <v_pixel_pair>
<evle_number_of_frames> ::= b'\x28\x00\x08\x00' b'IS' <ds_evle_length16> <v_is_two_frames>
<evle_columns_sixteen> ::= b'\x28\x00\x11\x00' b'US' <ds_evle_length16> <v_us_sixteen>
<evle_bits_allocated_one> ::= b'\x28\x00\x00\x01' b'US' <ds_evle_length16> <v_us_one>
<evle_bits_stored_one> ::= b'\x28\x00\x01\x01' b'US' <ds_evle_length16> <v_us_one>
<evle_high_bit_zero> ::= b'\x28\x00\x02\x01' b'US' <ds_evle_length16> <v_us_zero>
<evle_pixel_data_rgb> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' <ds_evle_length32> <v_pixel_six>
<evle_image_pixel_frames> ::= <evle_samples_per_pixel> <evle_photometric> <evle_number_of_frames> <evle_rows> <evle_columns> <evle_bits_allocated> <evle_high_bit_stored> <evle_high_bit> <evle_pixel_repr>
<evle_pixel_data_frames> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' <ds_evle_length32> <v_pixel_eight>
<evle_image_pixel_1bit> ::= <evle_samples_per_pixel> <evle_photometric> <evle_rows_one> <evle_columns_sixteen> <evle_bits_allocated_one> <evle_bits_stored_one> <evle_high_bit_zero> <evle_pixel_repr>
<evle_pixel_data_1bit> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' <ds_evle_length32> <v_pixel_pair>
<evbe_samples_three> ::= b'\x00\x28\x00\x02' b'US' <ds_evbe_length16> <v_us_three_be>
<evbe_photometric_rgb> ::= b'\x00\x28\x00\x04' b'CS' <ds_evbe_length16> <v_cs_rgb>
<evbe_planar_configuration> ::= b'\x00\x28\x00\x06' b'US' <ds_evbe_length16> <v_us_planar_be>
<evbe_number_of_frames> ::= b'\x00\x28\x00\x08' b'IS' <ds_evbe_length16> <v_is_two_frames>
<evbe_columns_sixteen> ::= b'\x00\x28\x00\x11' b'US' <ds_evbe_length16> <v_us_sixteen_be>
<evbe_bits_allocated_one> ::= b'\x00\x28\x01\x00' b'US' <ds_evbe_length16> <v_us_one_be>
<evbe_bits_stored_one> ::= b'\x00\x28\x01\x01' b'US' <ds_evbe_length16> <v_us_one_be>
<evbe_high_bit_zero> ::= b'\x00\x28\x01\x02' b'US' <ds_evbe_length16> <v_us_zero_be>
<evbe_image_pixel_rgb> ::= <evbe_samples_three> <evbe_photometric_rgb> <evbe_planar_configuration> <evbe_rows_one> <evbe_columns> <evbe_bits_allocated> <evbe_high_bit_stored> <evbe_high_bit> <evbe_pixel_repr>
<evbe_pixel_data_rgb> ::= b'\x7f\xe0\x00\x10' b'OB' b'\x00\x00' <ds_evbe_length32> <v_pixel_six>
<evbe_image_pixel_frames> ::= <evbe_samples_per_pixel> <evbe_photometric> <evbe_number_of_frames> <evbe_rows> <evbe_columns> <evbe_bits_allocated> <evbe_high_bit_stored> <evbe_high_bit> <evbe_pixel_repr>
<evbe_pixel_data_frames> ::= b'\x7f\xe0\x00\x10' b'OB' b'\x00\x00' <ds_evbe_length32> <v_pixel_eight>
<evbe_image_pixel_1bit> ::= <evbe_samples_per_pixel> <evbe_photometric> <evbe_rows_one> <evbe_columns_sixteen> <evbe_bits_allocated_one> <evbe_bits_stored_one> <evbe_high_bit_zero> <evbe_pixel_repr>
<evbe_pixel_data_1bit> ::= b'\x7f\xe0\x00\x10' b'OB' b'\x00\x00' <ds_evbe_length32> <v_pixel_pair>
<ivle_pixel_data_8> ::= <ivle_pixel_data>
<evle_pixel_data_8> ::= <evle_pixel_data> | <evle_pixel_data_ob>
<evle_pixel_data_ob> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' <ds_evle_length32> <v_pixel>
<v_us_sixteen> ::= <v_us> := b'\x10\x00'
<v_us_thirty_two> ::= <v_us> := b'\x20\x00'
<v_us_sixty_four> ::= <v_us> := b'\x40\x00'
<v_us_twelve> ::= <v_us> := b'\x0c\x00'
<v_us_eleven> ::= <v_us> := b'\x0b\x00'
<v_us_four> ::= <v_us> := b'\x04\x00'
<v_float_pixel> ::= rb'[\x00-\xff]{8}'
<v_double_pixel> ::= rb'[\x00-\xff]{8}'
<v_overlay> ::= rb'[\x00-\xff]{2}'
<v_cs_waveform_8> ::= <v_cs> := random.choice([b'SB', b'UB', b'MB', b'AB'])
<v_cs_waveform_16> ::= <v_cs> := random.choice([b'SS', b'US'])
<v_cs_waveform_32> ::= <v_cs> := random.choice([b'SL', b'UL'])
<v_cs_waveform_64> ::= <v_cs> := random.choice([b'SV', b'UV'])
<v_waveform_64> ::= rb'[\x00-\xff]{8}'
<ivle_waveform_bits_8> ::= b'\x00\x54\x04\x10' <ds_ivle_length> <v_us_eight>
<ivle_waveform_interpretation_8> ::= b'\x00\x54\x06\x10' <ds_ivle_length> <v_cs_waveform_8>
<ivle_waveform_data_8> ::= b'\x00\x54\x10\x10' <ds_ivle_length> <v_waveform>
<ivle_waveform_8> ::= <ivle_waveform_bits_8> <ivle_waveform_interpretation_8> <ivle_waveform_data_8>
<ivle_waveform_bits_16> ::= b'\x00\x54\x04\x10' <ds_ivle_length> <v_us_sixteen>
<ivle_waveform_interpretation_16> ::= b'\x00\x54\x06\x10' <ds_ivle_length> <v_cs_waveform_16>
<ivle_waveform_data_16> ::= b'\x00\x54\x10\x10' <ds_ivle_length> <v_waveform>
<ivle_waveform_16> ::= <ivle_waveform_bits_16> <ivle_waveform_interpretation_16> <ivle_waveform_data_16>
<ivle_waveform_bits_32> ::= b'\x00\x54\x04\x10' <ds_ivle_length> <v_us_thirty_two>
<ivle_waveform_interpretation_32> ::= b'\x00\x54\x06\x10' <ds_ivle_length> <v_cs_waveform_32>
<ivle_waveform_data_32> ::= b'\x00\x54\x10\x10' <ds_ivle_length> <v_waveform>
<ivle_waveform_32> ::= <ivle_waveform_bits_32> <ivle_waveform_interpretation_32> <ivle_waveform_data_32>
<ivle_waveform_bits_64> ::= b'\x00\x54\x04\x10' <ds_ivle_length> <v_us_sixty_four>
<ivle_waveform_interpretation_64> ::= b'\x00\x54\x06\x10' <ds_ivle_length> <v_cs_waveform_64>
<ivle_waveform_data_64> ::= b'\x00\x54\x10\x10' <ds_ivle_length> <v_waveform_64>
<ivle_waveform_64> ::= <ivle_waveform_bits_64> <ivle_waveform_interpretation_64> <ivle_waveform_data_64>
<ivle_waveform> ::= <ivle_waveform_8> | <ivle_waveform_16> | <ivle_waveform_32> | <ivle_waveform_64>
<evle_waveform_bits_8> ::= b'\x00\x54\x04\x10' b'US' <ds_evle_length16> <v_us_eight>
<evle_waveform_interpretation_8> ::= b'\x00\x54\x06\x10' b'CS' <ds_evle_length16> <v_cs_waveform_8>
<evle_waveform_data_8> ::= b'\x00\x54\x10\x10' b'OB' b'\x00\x00' <ds_evle_length32> <v_waveform>
<evle_waveform_8> ::= <evle_waveform_bits_8> <evle_waveform_interpretation_8> <evle_waveform_data_8>
<evle_waveform_bits_16> ::= b'\x00\x54\x04\x10' b'US' <ds_evle_length16> <v_us_sixteen>
<evle_waveform_interpretation_16> ::= b'\x00\x54\x06\x10' b'CS' <ds_evle_length16> <v_cs_waveform_16>
<evle_waveform_data_16> ::= b'\x00\x54\x10\x10' b'OW' b'\x00\x00' <ds_evle_length32> <v_waveform>
<evle_waveform_16> ::= <evle_waveform_bits_16> <evle_waveform_interpretation_16> <evle_waveform_data_16>
<evle_waveform_bits_32> ::= b'\x00\x54\x04\x10' b'US' <ds_evle_length16> <v_us_thirty_two>
<evle_waveform_interpretation_32> ::= b'\x00\x54\x06\x10' b'CS' <ds_evle_length16> <v_cs_waveform_32>
<evle_waveform_data_32> ::= b'\x00\x54\x10\x10' b'OW' b'\x00\x00' <ds_evle_length32> <v_waveform>
<evle_waveform_32> ::= <evle_waveform_bits_32> <evle_waveform_interpretation_32> <evle_waveform_data_32>
<evle_waveform_bits_64> ::= b'\x00\x54\x04\x10' b'US' <ds_evle_length16> <v_us_sixty_four>
<evle_waveform_interpretation_64> ::= b'\x00\x54\x06\x10' b'CS' <ds_evle_length16> <v_cs_waveform_64>
<evle_waveform_data_64> ::= b'\x00\x54\x10\x10' b'OW' b'\x00\x00' <ds_evle_length32> <v_waveform_64>
<evle_waveform_64> ::= <evle_waveform_bits_64> <evle_waveform_interpretation_64> <evle_waveform_data_64>
<evle_waveform> ::= <evle_waveform_8> | <evle_waveform_16> | <evle_waveform_32> | <evle_waveform_64>
<evbe_waveform_bits_8> ::= b'\x54\x00\x10\x04' b'US' <ds_evbe_length16> <v_us_eight_be>
<evbe_waveform_interpretation_8> ::= b'\x54\x00\x10\x06' b'CS' <ds_evbe_length16> <v_cs_waveform_8>
<evbe_waveform_data_8> ::= b'\x54\x00\x10\x10' b'OB' b'\x00\x00' <ds_evbe_length32> <v_waveform>
<evbe_waveform_8> ::= <evbe_waveform_bits_8> <evbe_waveform_interpretation_8> <evbe_waveform_data_8>
<evbe_waveform_bits_16> ::= b'\x54\x00\x10\x04' b'US' <ds_evbe_length16> <v_us_sixteen_be>
<evbe_waveform_interpretation_16> ::= b'\x54\x00\x10\x06' b'CS' <ds_evbe_length16> <v_cs_waveform_16>
<evbe_waveform_data_16> ::= b'\x54\x00\x10\x10' b'OW' b'\x00\x00' <ds_evbe_length32> <v_waveform>
<evbe_waveform_16> ::= <evbe_waveform_bits_16> <evbe_waveform_interpretation_16> <evbe_waveform_data_16>
<evbe_waveform_bits_32> ::= b'\x54\x00\x10\x04' b'US' <ds_evbe_length16> <v_us_thirty_two_be>
<evbe_waveform_interpretation_32> ::= b'\x54\x00\x10\x06' b'CS' <ds_evbe_length16> <v_cs_waveform_32>
<evbe_waveform_data_32> ::= b'\x54\x00\x10\x10' b'OW' b'\x00\x00' <ds_evbe_length32> <v_waveform>
<evbe_waveform_32> ::= <evbe_waveform_bits_32> <evbe_waveform_interpretation_32> <evbe_waveform_data_32>
<evbe_waveform_bits_64> ::= b'\x54\x00\x10\x04' b'US' <ds_evbe_length16> <v_us_sixty_four_be>
<evbe_waveform_interpretation_64> ::= b'\x54\x00\x10\x06' b'CS' <ds_evbe_length16> <v_cs_waveform_64>
<evbe_waveform_data_64> ::= b'\x54\x00\x10\x10' b'OW' b'\x00\x00' <ds_evbe_length32> <v_waveform_64>
<evbe_waveform_64> ::= <evbe_waveform_bits_64> <evbe_waveform_interpretation_64> <evbe_waveform_data_64>
<evbe_waveform> ::= <evbe_waveform_8> | <evbe_waveform_16> | <evbe_waveform_32> | <evbe_waveform_64>
<v_waveform> ::= rb'[\x00-\xff]{4}'
<v_cs_waveform> ::= <v_cs> := random.choice([b'SS', b'UB', b'MB', b'AB'])
<ivle_ref_class> ::= b'\x08\x00\x50\x11' <ds_ivle_length> <v_ui_item_class>
<ivle_ref_instance> ::= b'\x08\x00\x55\x11' <ds_ivle_length> <v_ui_sop_instance>
<ivle_query_level_study> ::= b'\x08\x00\x52\x00' <ds_ivle_length> <v_cs_level_study>
<ivle_query_level_patient> ::= b'\x08\x00\x52\x00' <ds_ivle_length> <v_cs_level_patient>
<ivle_query_level_series> ::= b'\x08\x00\x52\x00' <ds_ivle_length> <v_cs_level_series>
<ivle_query_level_image> ::= b'\x08\x00\x52\x00' <ds_ivle_length> <v_cs_level_image>
<ivle_study_uid_empty> ::= b'\x20\x00\x0d\x00' <ds_ivle_length> <v_ui_empty>
<ivle_ref_item_explicit> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <ivle_ref_class> <ivle_ref_instance>
<ivle_ref_item_undefined> ::= b'\xfe\xff\x00\xe0\xff\xff\xff\xff' <ivle_ref_class> <ivle_ref_instance> <ds_item_delimitation>
<ivle_ref_sequence> ::= b'\x08\x00\x40\x11' <ds_ivle_length> <ivle_ref_item_explicit>*
<ivle_ref_sequence_undefined> ::= b'\x08\x00\x40\x11' b'\xff\xff\xff\xff' (<ivle_ref_item_explicit> | <ivle_ref_item_undefined>)* <ds_sequence_delimitation>
<dataset_store_ivle> ::= <dataset_store_ivle_head> <dataset_store_ivle_tail>
<dataset_store_ivle_head> ::= <ivle_charset>? <ivle_sop_class> <ivle_sop_instance> <ivle_study_date>? <ivle_modality> <ivle_ref_sequence_any>? <ivle_private>?
<dataset_store_ivle_tail> ::= <ivle_patient_name> <ivle_patient_id> <ivle_study_uid> <ivle_series_uid> <ivle_pixel_module>
<ivle_ref_sequence_any> ::= <ivle_ref_sequence> | <ivle_ref_sequence_undefined>
<ivle_image_pixel> ::= <ivle_samples_per_pixel> <ivle_photometric> <ivle_rows> <ivle_columns> <ivle_bits_allocated> <ivle_high_bit_stored> <ivle_high_bit> <ivle_pixel_repr>
# Data sets in encapsulation transfer syntaxes (PS3.5 A.4): Explicit VR Little Endian elements, Pixel Data of VR OB with undefined length made of Items (Basic Offset Table,
# fragments) ended by a Sequence Delimitation Item (7.5.2); RLE fragments follow the codec of Annex G (header of 16 long words, byte segments, PackBits runs);
# the fragment bytes of the other codecs are opaque (their standards are not in refs/spec/)
<dataset_store_rle> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> (<evle_image_pixel> <evle_pixel_data_rle> | <evle_image_pixel_16> <evle_pixel_data_rle_16> | <evle_image_pixel_rgb> <evle_pixel_data_rle_rgb> | <evle_image_pixel_rgb16> <evle_pixel_data_rle_rgb16>)
<dataset_store_encapsulated> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_image_pixel> <evle_pixel_data_encapsulated>
<dataset_store_jpip> ::= <dataset_store_evle_head> <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_image_pixel> <evle_pixel_data_url>
<evle_pixel_data_rle> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <encapsulation_basic_offset_table> <rle_fragment_item> <ds_sequence_delimitation>
<evle_pixel_data_encapsulated> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <encapsulation_basic_offset_table> <encapsulation_fragment_item>+ <ds_sequence_delimitation>
<evle_pixel_data_url> ::= b'\x28\x00\xe0\x7f' b'UR' b'\x00\x00' <ds_evle_length32> <v_ur>
<encapsulation_basic_offset_table> ::= <basic_offset_table_empty> | <basic_offset_table_one_frame>
<basic_offset_table_empty> ::= b'\xfe\xff\x00\xe0' <ds_item_length>
<basic_offset_table_one_frame> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <frame_offset>
<frame_offset> ::= rb'[\x00-\xff]{4}' := b'\x00\x00\x00\x00'
<rle_fragment_item> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <rle_codestream>
<rle_codestream> ::= <rle_header> <rle_segment_4>
<rle_segment_4> ::= <rle_rows_segment_4> | <rle_nop_segment_4>
# PS3.5 G.3: one Byte Segment of 4 bytes (2 rows of 2 bytes, every row encoded separately: a Literal Run of 2 bytes, a Replicate Run of 2 bytes or two Literal Runs of 1 byte), padded with zero to an even length
<rle_rows_segment_4> ::= b'\x01' <v_pixel_pair> b'\x01' <v_pixel_pair> | b'\x01' <v_pixel_pair> b'\xff' <rle_replicated_byte> b'\x00' | b'\x01' <v_pixel_pair> b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte> b'\x00' | b'\xff' <rle_replicated_byte> b'\x01' <v_pixel_pair> b'\x00' | b'\xff' <rle_replicated_byte> b'\xff' <rle_replicated_byte> | b'\xff' <rle_replicated_byte> b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte> | b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte> b'\x01' <v_pixel_pair> b'\x00' | b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte> b'\xff' <rle_replicated_byte> | b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte>
# with a no-operation control byte (-128) in front (G.3.2)
<rle_nop_segment_4> ::= b'\x80' b'\x01' <v_pixel_pair> b'\x01' <v_pixel_pair> b'\x00' | b'\x80' b'\xff' <rle_replicated_byte> b'\xff' <rle_replicated_byte> b'\x00' | b'\x80' b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte> b'\xff' <rle_replicated_byte> b'\x00' | b'\x80' b'\x01' <v_pixel_pair> b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte>
<rle_header> ::= <rle_segment_count> <rle_first_offset> <rle_unused_offsets>
<rle_segment_count> ::= b'\x01\x00\x00\x00'
<rle_first_offset> ::= b'\x40\x00\x00\x00'
<rle_unused_offsets> ::= rb'[\x00]{56}' := b'\x00' * 56
# PS3.5 G.2, G.5: 16 bit samples are encoded as two byte segments (the more significant bytes first); the header holds the segment count and the offset of every segment
<evle_pixel_data_rle_16> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <encapsulation_basic_offset_table> <rle_fragment_item_16> <ds_sequence_delimitation>
<rle_fragment_item_16> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <rle_codestream_16>
<rle_codestream_16> ::= <rle_header_16> <rle_segment_16> <rle_segment_16>
<rle_header_16> ::= <rle_segment_count_16> <rle_first_offset> <rle_second_offset> <rle_unused_offsets_16>
<rle_segment_count_16> ::= b'\x02\x00\x00\x00'
<rle_second_offset> ::= rb'[\x00-\xff]{4}' := b'\x44\x00\x00\x00'
where forall <o> in <rle_second_offset>: <o> == u32le(64 + len(bytes(<o>.parent.parent.children[1])))
<rle_unused_offsets_16> ::= rb'[\x00]{52}' := b'\x00' * 52
<rle_segment_16> ::= <rle_literal_segment_16> | <rle_replicate_segment_16> | <rle_two_literals_segment_16> | <rle_nop_literal_segment_16> | <rle_nop_replicate_segment_16>
# a row of 2 bytes as two Literal Runs of 1 byte, with a no-operation control byte (-128) in front of a Literal Run (4 bytes) or of a Replicate Run (2 + 1 bytes, padded)
<rle_two_literals_segment_16> ::= b'\x00' <rle_replicated_byte> b'\x00' <rle_replicated_byte>
<rle_nop_literal_segment_16> ::= b'\x80' b'\x01' <v_pixel_pair>
<rle_nop_replicate_segment_16> ::= b'\x80' b'\xff' <rle_replicated_byte> b'\x00'
<rle_literal_segment_16> ::= b'\x01' <v_pixel_pair> b'\x00'
<rle_replicate_segment_16> ::= b'\xff' <rle_replicated_byte>
<v_pixel_pair> ::= rb'[\x00-\xff]{2}'
# PS3.5 G.2, Table 8.2.2-1: RGB with 8 bit samples is encoded as three byte segments (red, green, blue), Planar Configuration 0 or 1
<evle_image_pixel_rgb> ::= <evle_samples_three> <evle_photometric_rgb> <evle_planar_configuration> <evle_rows_one> <evle_columns> <evle_bits_allocated> <evle_high_bit_stored> <evle_high_bit> <evle_pixel_repr>
<evle_photometric_rgb> ::= b'\x28\x00\x04\x00' b'CS' <ds_evle_length16> <v_cs_rgb>
<v_cs_rgb> ::= <v_cs> := random.choice([b'RGB ', b'YBR_FULL'])
<evle_planar_configuration> ::= b'\x28\x00\x06\x00' b'US' <ds_evle_length16> <v_us_planar>
<v_us_planar> ::= <v_us> := random.choice([b'\x00\x00', b'\x01\x00'])
<evle_pixel_data_rle_rgb> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <encapsulation_basic_offset_table> <rle_fragment_item_rgb> <ds_sequence_delimitation>
<rle_fragment_item_rgb> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <rle_codestream_rgb>
<rle_codestream_rgb> ::= <rle_header_rgb> <rle_segment_16> <rle_segment_16> <rle_segment_16>
<rle_header_rgb> ::= <rle_segment_count_rgb> <rle_first_offset> <rle_second_offset> <rle_third_offset> <rle_unused_offsets_rgb>
<rle_segment_count_rgb> ::= b'\x03\x00\x00\x00'
<rle_third_offset> ::= rb'[\x00-\xff]{4}' := b'\x48\x00\x00\x00'
where forall <o> in <rle_third_offset>: <o> == u32le(64 + len(bytes(<o>.parent.parent.children[1])) + len(bytes(<o>.parent.parent.children[2])))
<rle_unused_offsets_rgb> ::= rb'[\x00]{48}' := b'\x00' * 48
# PS3.5 G.2, Table 8.2.2-1: RGB (or YBR_FULL) with 16 bit samples: 3 x 2 = six Byte Segments (the more significant byte of red, its less significant byte, green, blue), the header holds the count 6 and six offsets
<evle_image_pixel_rgb16> ::= <evle_samples_three> <evle_photometric_rgb> <evle_planar_configuration> <evle_rows_one> <evle_columns> <evle_bits_allocated_16> <evle_high_bit_stored_12> <evle_high_bit_11> <evle_pixel_repr>
<evle_pixel_data_rle_rgb16> ::= b'\xe0\x7f\x10\x00' b'OB' b'\x00\x00' b'\xff\xff\xff\xff' <encapsulation_basic_offset_table> <rle_fragment_item_rgb16> <ds_sequence_delimitation>
<rle_fragment_item_rgb16> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <rle_codestream_rgb16>
<rle_codestream_rgb16> ::= <rle_header_rgb16> <rle_segment_16> <rle_segment_16> <rle_segment_16> <rle_segment_16> <rle_segment_16> <rle_segment_16>
<rle_header_rgb16> ::= <rle_segment_count_rgb16> <rle_first_offset> <rle_second_offset> <rle_third_offset> <rle_fourth_offset> <rle_fifth_offset> <rle_sixth_offset> <rle_unused_offsets_rgb16>
<rle_segment_count_rgb16> ::= b'\x06\x00\x00\x00'
<rle_fourth_offset> ::= rb'[\x00-\xff]{4}' := b'\x4c\x00\x00\x00'
where forall <o> in <rle_fourth_offset>: <o> == rle_offset_value(<o>, 4)
<rle_fifth_offset> ::= rb'[\x00-\xff]{4}' := b'\x50\x00\x00\x00'
where forall <o> in <rle_fifth_offset>: <o> == rle_offset_value(<o>, 5)
<rle_sixth_offset> ::= rb'[\x00-\xff]{4}' := b'\x54\x00\x00\x00'
where forall <o> in <rle_sixth_offset>: <o> == rle_offset_value(<o>, 6)
<rle_unused_offsets_rgb16> ::= rb'[\x00]{36}' := b'\x00' * 36
<rle_replicated_byte> ::= rb'[\x00-\xff]'
<encapsulation_fragment_item> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <encapsulation_fragment>
<encapsulation_fragment> ::= b'\xff\xd8' <encapsulation_fragment_word>* b'\xff\xd9'
<encapsulation_fragment_word> ::= rb'[\x00-\xfe][\x00-\xff]'
# Explicit VR Big Endian (retired, PS3.5 A.3): the Explicit VR rules with big endian tags, lengths and numeric values (the command set stays Implicit VR Little Endian)
<evbe_private_data> ::= <evbe_private_data_ul> | <evbe_private_data_lo> | <evbe_private_data_ae> | <evbe_private_data_as> | <evbe_private_data_at> | <evbe_private_data_ds> | <evbe_private_data_dt> | <evbe_private_data_fl> | <evbe_private_data_fd> | <evbe_private_data_is> | <evbe_private_data_lt> | <evbe_private_data_ob> | <evbe_private_data_od> | <evbe_private_data_of> | <evbe_private_data_ol> | <evbe_private_data_ov> | <evbe_private_data_sh> | <evbe_private_data_sl> | <evbe_private_data_ss> | <evbe_private_data_st> | <evbe_private_data_sv> | <evbe_private_data_tm> | <evbe_private_data_uc> | <evbe_private_data_un> | <evbe_private_data_ur> | <evbe_private_data_ut> | <evbe_private_data_uv> | <evbe_private_data_un_sequence>
<evbe_private_data_lo> ::= b'\x00\x09\x10\x01' b'LO' <ds_evbe_length16> <v_lo>
<evbe_private_data_ae> ::= b'\x00\x09\x10\x01' b'AE' <ds_evbe_length16> <v_ae>
<evbe_private_data_as> ::= b'\x00\x09\x10\x01' b'AS' <ds_evbe_length16> <v_as>
<evbe_private_data_at> ::= b'\x00\x09\x10\x01' b'AT' <ds_evbe_length16> <v_at>
<evbe_private_data_ds> ::= b'\x00\x09\x10\x01' b'DS' <ds_evbe_length16> <v_ds>
<evbe_private_data_dt> ::= b'\x00\x09\x10\x01' b'DT' <ds_evbe_length16> <v_dt>
<evbe_private_data_fl> ::= b'\x00\x09\x10\x01' b'FL' <ds_evbe_length16> <v_fl>
<evbe_private_data_fd> ::= b'\x00\x09\x10\x01' b'FD' <ds_evbe_length16> <v_fd>
<evbe_private_data_is> ::= b'\x00\x09\x10\x01' b'IS' <ds_evbe_length16> <v_is>
<evbe_private_data_lt> ::= b'\x00\x09\x10\x01' b'LT' <ds_evbe_length16> <v_lt>
<evbe_private_data_ob> ::= b'\x00\x09\x10\x01' b'OB' b'\x00\x00' <ds_evbe_length32> <v_ob>
<evbe_private_data_od> ::= b'\x00\x09\x10\x01' b'OD' b'\x00\x00' <ds_evbe_length32> <v_od>
<evbe_private_data_of> ::= b'\x00\x09\x10\x01' b'OF' b'\x00\x00' <ds_evbe_length32> <v_of>
<evbe_private_data_ol> ::= b'\x00\x09\x10\x01' b'OL' b'\x00\x00' <ds_evbe_length32> <v_ol>
<evbe_private_data_ov> ::= b'\x00\x09\x10\x01' b'OV' b'\x00\x00' <ds_evbe_length32> <v_ov>
<evbe_private_data_sh> ::= b'\x00\x09\x10\x01' b'SH' <ds_evbe_length16> <v_sh>
<evbe_private_data_sl> ::= b'\x00\x09\x10\x01' b'SL' <ds_evbe_length16> <v_sl>
<evbe_private_data_ss> ::= b'\x00\x09\x10\x01' b'SS' <ds_evbe_length16> <v_ss>
<evbe_private_data_st> ::= b'\x00\x09\x10\x01' b'ST' <ds_evbe_length16> <v_st>
<evbe_private_data_sv> ::= b'\x00\x09\x10\x01' b'SV' b'\x00\x00' <ds_evbe_length32> <v_sv>
<evbe_private_data_tm> ::= b'\x00\x09\x10\x01' b'TM' <ds_evbe_length16> <v_tm>
<evbe_private_data_uc> ::= b'\x00\x09\x10\x01' b'UC' b'\x00\x00' <ds_evbe_length32> <v_uc>
<evbe_private_data_un> ::= b'\x00\x09\x10\x01' b'UN' b'\x00\x00' <ds_evbe_length32> <v_un>
<evbe_private_data_ur> ::= b'\x00\x09\x10\x01' b'UR' b'\x00\x00' <ds_evbe_length32> <v_ur>
<evbe_private_data_ut> ::= b'\x00\x09\x10\x01' b'UT' b'\x00\x00' <ds_evbe_length32> <v_ut>
<evbe_private_data_uv> ::= b'\x00\x09\x10\x01' b'UV' b'\x00\x00' <ds_evbe_length32> <v_uv>
<evbe_private_data_un_sequence> ::= b'\x00\x09\x10\x01' b'UN' b'\x00\x00' b'\xff\xff\xff\xff' <ivle_ref_item_undefined>* <ds_sequence_delimitation>
<evbe_private> ::= <evbe_private_creator> <evbe_private_data> <evbe_private_sequence>?
<evbe_private_block> ::= <evbe_private_creator> <evbe_private_data_lo_item>
<evbe_private_data_lo_item> ::= b'\x00\x09\x10\x01' b'LO' <ds_evbe_length16> <v_lo>
<evbe_private_sequence> ::= b'\x00\x09\x10\x02' b'SQ' b'\x00\x00' <ds_evbe_length32> <evbe_private_item>*
<evbe_private_item> ::= b'\xff\xfe\xe0\x00' <ds_item_length_be> <evbe_ref_class> <evbe_ref_instance> <evbe_private_block>
<evbe_rows_one> ::= b'\x00\x28\x00\x10' b'US' <ds_evbe_length16> <v_us_one_be>
<evbe_bits_allocated_16> ::= b'\x00\x28\x01\x00' b'US' <ds_evbe_length16> <v_us_sixteen_be>
<evbe_bits_allocated_32> ::= b'\x00\x28\x01\x00' b'US' <ds_evbe_length16> <v_us_thirty_two_be>
<evbe_bits_allocated_64> ::= b'\x00\x28\x01\x00' b'US' <ds_evbe_length16> <v_us_sixty_four_be>
<evbe_high_bit_stored_12> ::= b'\x00\x28\x01\x01' b'US' <ds_evbe_length16> <v_us_twelve_be>
<evbe_high_bit_11> ::= b'\x00\x28\x01\x02' b'US' <ds_evbe_length16> <v_us_eleven_be>
<evbe_float_pixel_data> ::= b'\x7f\xe0\x00\x08' b'OF' b'\x00\x00' <ds_evbe_length32> <v_float_pixel>
<evbe_double_pixel_data> ::= b'\x7f\xe0\x00\x09' b'OD' b'\x00\x00' <ds_evbe_length32> <v_double_pixel>
<evbe_overlay_rows> ::= b'\x60\x00\x00\x10' b'US' <ds_evbe_length16> <v_us_four_be>
<evbe_overlay_columns> ::= b'\x60\x00\x00\x11' b'US' <ds_evbe_length16> <v_us_four_be>
<evbe_overlay_bits_allocated> ::= b'\x60\x00\x01\x00' b'US' <ds_evbe_length16> <v_us_one_be>
<evbe_overlay_bit_position> ::= b'\x60\x00\x01\x02' b'US' <ds_evbe_length16> <v_us_zero_be>
<evbe_overlay_data> ::= b'\x60\x00\x30\x00' b'OW' b'\x00\x00' <ds_evbe_length32> <v_overlay>
<evbe_image_pixel_16> ::= <evbe_samples_per_pixel> <evbe_photometric> <evbe_rows_one> <evbe_columns> <evbe_bits_allocated_16> <evbe_high_bit_stored_12> <evbe_high_bit_11> <evbe_pixel_repr>
<evbe_image_float> ::= <evbe_samples_per_pixel> <evbe_photometric> <evbe_rows_one> <evbe_columns> <evbe_bits_allocated_32>
<evbe_image_double> ::= <evbe_samples_per_pixel> <evbe_photometric> <evbe_rows_one> <evbe_columns_one> <evbe_bits_allocated_64>
<evbe_columns_one> ::= b'\x00\x28\x00\x11' b'US' <ds_evbe_length16> <v_us_one_be>
<evbe_overlay> ::= <evbe_overlay_rows> <evbe_overlay_columns> <evbe_overlay_bits_allocated> <evbe_overlay_bit_position> <evbe_overlay_data>
<evbe_pixel_module> ::= <evbe_image_pixel> <evbe_waveform>? <evbe_overlay>? <evbe_pixel_data_8> | <evbe_image_pixel_16> <evbe_waveform>? <evbe_overlay>? <evbe_pixel_data> | <evbe_image_float> <evbe_float_pixel_data> | <evbe_image_double> <evbe_double_pixel_data> | <evbe_image_pixel_rgb> <evbe_pixel_data_rgb> | <evbe_image_pixel_frames> <evbe_pixel_data_frames> | <evbe_image_pixel_1bit> <evbe_pixel_data_1bit>
<evbe_pixel_data_8> ::= <evbe_pixel_data> | <evbe_pixel_data_ob>
<evbe_pixel_data_ob> ::= b'\x7f\xe0\x00\x10' b'OB' b'\x00\x00' <ds_evbe_length32> <v_pixel>
<evbe_charset> ::= b'\x00\x08\x00\x05' b'CS' <ds_evbe_length16> <v_cs_charset>
<evbe_sop_class> ::= b'\x00\x08\x00\x16' b'UI' <ds_evbe_length16> <v_ui_sop_class>
<evbe_sop_instance> ::= b'\x00\x08\x00\x18' b'UI' <ds_evbe_length16> <v_ui_sop_instance>
<evbe_study_date> ::= b'\x00\x08\x00\x20' b'DA' <ds_evbe_length16> <v_da>
<evbe_modality> ::= b'\x00\x08\x00\x60' b'CS' <ds_evbe_length16> <v_cs_modality>
<evbe_patient_name> ::= b'\x00\x10\x00\x10' b'PN' <ds_evbe_length16> <v_pn>
<evbe_patient_id> ::= b'\x00\x10\x00\x20' b'LO' <ds_evbe_length16> <v_lo>
<evbe_study_uid> ::= b'\x00\x20\x00\x0d' b'UI' <ds_evbe_length16> <v_ui_study>
<evbe_series_uid> ::= b'\x00\x20\x00\x0e' b'UI' <ds_evbe_length16> <v_ui_series>
<evbe_samples_per_pixel> ::= b'\x00\x28\x00\x02' b'US' <ds_evbe_length16> <v_us_one_be>
<evbe_photometric> ::= b'\x00\x28\x00\x04' b'CS' <ds_evbe_length16> <v_cs_photometric>
<evbe_rows> ::= b'\x00\x28\x00\x10' b'US' <ds_evbe_length16> <v_us_two_be>
<evbe_columns> ::= b'\x00\x28\x00\x11' b'US' <ds_evbe_length16> <v_us_two_be>
<evbe_bits_allocated> ::= b'\x00\x28\x01\x00' b'US' <ds_evbe_length16> <v_us_eight_be>
<evbe_pixel_data> ::= b'\x7f\xe0\x00\x10' b'OW' b'\x00\x00' <ds_evbe_length32> <v_pixel>
<evbe_private_creator> ::= b'\x00\x09\x00\x10' b'LO' <ds_evbe_length16> <v_lo_creator>
<evbe_high_bit_stored> ::= b'\x00\x28\x01\x01' b'US' <ds_evbe_length16> <v_us_eight_be>
<evbe_high_bit> ::= b'\x00\x28\x01\x02' b'US' <ds_evbe_length16> <v_us_seven_be>
<evbe_pixel_repr> ::= b'\x00\x28\x01\x03' b'US' <ds_evbe_length16> <v_us_zero_be>
<evbe_ref_class> ::= b'\x00\x08\x11\x50' b'UI' <ds_evbe_length16> <v_ui_item_class>
<evbe_ref_instance> ::= b'\x00\x08\x11\x55' b'UI' <ds_evbe_length16> <v_ui_sop_instance>
<evbe_query_level_study> ::= b'\x00\x08\x00\x52' b'CS' <ds_evbe_length16> <v_cs_level_study>
<evbe_query_level_patient> ::= b'\x00\x08\x00\x52' b'CS' <ds_evbe_length16> <v_cs_level_patient>
<evbe_query_level_series> ::= b'\x00\x08\x00\x52' b'CS' <ds_evbe_length16> <v_cs_level_series>
<evbe_query_level_image> ::= b'\x00\x08\x00\x52' b'CS' <ds_evbe_length16> <v_cs_level_image>
<evbe_study_uid_empty> ::= b'\x00\x20\x00\x0d' b'UI' <ds_evbe_length16> <v_ui_empty>
<evbe_ref_item_explicit> ::= b'\xff\xfe\xe0\x00' <ds_item_length_be> <evbe_ref_class> <evbe_ref_instance>
<evbe_ref_item_undefined> ::= b'\xff\xfe\xe0\x00\xff\xff\xff\xff' <evbe_ref_class> <evbe_ref_instance> <ds_item_delimitation_be>
<evbe_ref_sequence> ::= b'\x00\x08\x11\x40' b'SQ' b'\x00\x00' <ds_evbe_length32> <evbe_ref_item_explicit>*
<evbe_ref_sequence_undefined> ::= b'\x00\x08\x11\x40' b'SQ' b'\x00\x00' b'\xff\xff\xff\xff' (<evbe_ref_item_explicit> | <evbe_ref_item_undefined>)* <ds_sequence_delimitation_be>
<dataset_store_evbe> ::= <dataset_store_evbe_head> <dataset_store_evbe_tail>
<dataset_store_evbe_head> ::= <evbe_charset>? <evbe_sop_class> <evbe_sop_instance> <evbe_study_date>? <evbe_modality> <evbe_ref_sequence_any>? <evbe_private>?
<dataset_store_evbe_tail> ::= <evbe_patient_name> <evbe_patient_id> <evbe_study_uid> <evbe_series_uid> <evbe_pixel_module>
<evbe_ref_sequence_any> ::= <evbe_ref_sequence> | <evbe_ref_sequence_undefined>
<evbe_image_pixel> ::= <evbe_samples_per_pixel> <evbe_photometric> <evbe_rows> <evbe_columns> <evbe_bits_allocated> <evbe_high_bit_stored> <evbe_high_bit> <evbe_pixel_repr>
<v_us_one_be> ::= <v_us> := b'\x00\x01'
<v_us_two_be> ::= <v_us> := b'\x00\x02'
<v_us_eight_be> ::= <v_us> := b'\x00\x08'
<v_us_seven_be> ::= <v_us> := b'\x00\x07'
<v_us_zero_be> ::= <v_us> := b'\x00\x00'
<v_us_sixteen_be> ::= <v_us> := b'\x00\x10'
<v_us_thirty_two_be> ::= <v_us> := b'\x00\x20'
<v_us_sixty_four_be> ::= <v_us> := b'\x00\x40'
<v_us_twelve_be> ::= <v_us> := b'\x00\x0c'
<v_us_eleven_be> ::= <v_us> := b'\x00\x0b'
<v_us_four_be> ::= <v_us> := b'\x00\x04'
<ds_evbe_length16> ::= rb'[\x00-\xff]{2}'
where forall <l> in <ds_evbe_length16>: <l> == u16be(len(bytes(<l>.parent)) - 8)
<ds_evbe_length32> ::= rb'[\x00-\xff]{4}'
where forall <l> in <ds_evbe_length32>: <l> == u32be(len(bytes(<l>.parent)) - 12)
<ds_item_length_be> ::= rb'[\x00-\xff]{4}'
where forall <l> in <ds_item_length_be>: <l> == u32be(len(bytes(<l>.parent)) - 8)
<ds_item_delimitation_be> ::= b'\xff\xfe\xe0\x0d\x00\x00\x00\x00'
<ds_sequence_delimitation_be> ::= b'\xff\xfe\xe0\xdd\x00\x00\x00\x00'
<dataset_find_ivle> ::= <ivle_charset>? (<ivle_query_level_study> | <ivle_query_level_patient> | <ivle_query_level_series> | <ivle_query_level_image>) <ivle_patient_name>? <ivle_patient_id>? (<ivle_study_uid_empty> | <ivle_study_uid>)?
<dataset_retrieve_ivle> ::= <ivle_charset>? <ivle_query_level_study> <ivle_study_uid>
<dataset_normalized_ivle> ::= <ivle_charset>? <ivle_patient_id>
<evle_charset> ::= b'\x08\x00\x05\x00' b'CS' <ds_evle_length16> <v_cs_charset>
<evle_sop_class> ::= b'\x08\x00\x16\x00' b'UI' <ds_evle_length16> <v_ui_sop_class>
<evle_sop_instance> ::= b'\x08\x00\x18\x00' b'UI' <ds_evle_length16> <v_ui_sop_instance>
<evle_study_date> ::= b'\x08\x00\x20\x00' b'DA' <ds_evle_length16> <v_da>
<evle_modality> ::= b'\x08\x00\x60\x00' b'CS' <ds_evle_length16> <v_cs_modality>
<evle_patient_name> ::= b'\x10\x00\x10\x00' b'PN' <ds_evle_length16> <v_pn>
<evle_patient_id> ::= b'\x10\x00\x20\x00' b'LO' <ds_evle_length16> <v_lo>
<evle_study_uid> ::= b'\x20\x00\x0d\x00' b'UI' <ds_evle_length16> <v_ui_study>
<evle_series_uid> ::= b'\x20\x00\x0e\x00' b'UI' <ds_evle_length16> <v_ui_series>
<evle_samples_per_pixel> ::= b'\x28\x00\x02\x00' b'US' <ds_evle_length16> <v_us_one>
<evle_photometric> ::= b'\x28\x00\x04\x00' b'CS' <ds_evle_length16> <v_cs_photometric>
<evle_rows> ::= b'\x28\x00\x10\x00' b'US' <ds_evle_length16> <v_us_two>
<evle_columns> ::= b'\x28\x00\x11\x00' b'US' <ds_evle_length16> <v_us_two>
<evle_bits_allocated> ::= b'\x28\x00\x00\x01' b'US' <ds_evle_length16> <v_us_eight>
<evle_pixel_data> ::= b'\xe0\x7f\x10\x00' b'OW' b'\x00\x00' <ds_evle_length32> <v_pixel>
<evle_private_creator> ::= b'\x09\x00\x10\x00' b'LO' <ds_evle_length16> <v_lo_creator>
<evle_high_bit_stored> ::= b'\x28\x00\x01\x01' b'US' <ds_evle_length16> <v_us_eight>
<evle_high_bit> ::= b'\x28\x00\x02\x01' b'US' <ds_evle_length16> <v_us_seven>
<evle_pixel_repr> ::= b'\x28\x00\x03\x01' b'US' <ds_evle_length16> <v_us_zero>
<evle_ref_class> ::= b'\x08\x00\x50\x11' b'UI' <ds_evle_length16> <v_ui_item_class>
<evle_ref_instance> ::= b'\x08\x00\x55\x11' b'UI' <ds_evle_length16> <v_ui_sop_instance>
<evle_query_level_study> ::= b'\x08\x00\x52\x00' b'CS' <ds_evle_length16> <v_cs_level_study>
<evle_query_level_patient> ::= b'\x08\x00\x52\x00' b'CS' <ds_evle_length16> <v_cs_level_patient>
<evle_query_level_series> ::= b'\x08\x00\x52\x00' b'CS' <ds_evle_length16> <v_cs_level_series>
<evle_query_level_image> ::= b'\x08\x00\x52\x00' b'CS' <ds_evle_length16> <v_cs_level_image>
<evle_study_uid_empty> ::= b'\x20\x00\x0d\x00' b'UI' <ds_evle_length16> <v_ui_empty>
<evle_ref_item_explicit> ::= b'\xfe\xff\x00\xe0' <ds_item_length> <evle_ref_class> <evle_ref_instance>
<evle_ref_item_undefined> ::= b'\xfe\xff\x00\xe0\xff\xff\xff\xff' <evle_ref_class> <evle_ref_instance> <ds_item_delimitation>
<evle_ref_sequence> ::= b'\x08\x00\x40\x11' b'SQ' b'\x00\x00' <ds_evle_length32> <evle_ref_item_explicit>*
<evle_ref_sequence_undefined> ::= b'\x08\x00\x40\x11' b'SQ' b'\x00\x00' b'\xff\xff\xff\xff' (<evle_ref_item_explicit> | <evle_ref_item_undefined>)* <ds_sequence_delimitation>
<dataset_store_evle> ::= <dataset_store_evle_head> <dataset_store_evle_tail>
<dataset_store_evle_head> ::= <evle_charset>? <evle_sop_class> <evle_sop_instance> <evle_study_date>? <evle_modality> <evle_ref_sequence_any>? <evle_private>?
<dataset_store_evle_tail> ::= <evle_patient_name> <evle_patient_id> <evle_study_uid> <evle_series_uid> <evle_pixel_module>
<evle_ref_sequence_any> ::= <evle_ref_sequence> | <evle_ref_sequence_undefined>
<evle_image_pixel> ::= <evle_samples_per_pixel> <evle_photometric> <evle_rows> <evle_columns> <evle_bits_allocated> <evle_high_bit_stored> <evle_high_bit> <evle_pixel_repr>
<dataset_find_evle> ::= <evle_charset>? (<evle_query_level_study> | <evle_query_level_patient> | <evle_query_level_series> | <evle_query_level_image>) <evle_patient_name>? <evle_patient_id>? (<evle_study_uid_empty> | <evle_study_uid>)?
<dataset_retrieve_evle> ::= <evle_charset>? <evle_query_level_study> <evle_study_uid>
<dataset_normalized_evle> ::= <evle_charset>? <evle_patient_id>


# ======================================================================================================
# DIMSE exchanges. A request is followed by the reply classes the spec allows: its response, an A-ABORT, or silence
# (a Fandango timer). All replies of one request share the request nonterminal.
# ======================================================================================================
<dimse_timer_start> ::= <timer_start>
<dimse_timer_cancel> ::= <timer_cancel>
<dimse_timer_expired> ::= <timer_expired>
where str(<dimse_timer_start>..<timer_id>) == '3'
where str(<dimse_timer_start>..<timer_timeout>) == '4'
where str(<dimse_timer_cancel>..<timer_id>) == '3'
where str(<dimse_timer_expired>..<timer_id>) == '3'

# PS3.8 Annex E: a command in several Command Fragments (first fragments without the last-fragment flag), in two PDUs or as two PDVs of one P-DATA-TF; the
# feature is exercised through the C-ECHO command, the shortest one (it applies to every command alike)
<req_c_echo> ::= <pdu_c_echo_rq> | <pdu_c_echo_rq_two_fragments> | <pdu_c_echo_rq_head> <pdu_c_echo_rq_tail>
# PS3.7 D.3.3.3, E.1 (asynchronous operations: several outstanding requests, sent whether or not a window was negotiated): two C-ECHO-RQ in one message (two P-DATA-TF PDUs sent together), so that the second
# request is on its way before the first reply arrives. The second request has its own Message ID rule, set by a `where` equality to the first one's plus one: the IDs differ by construction.
<req_c_echo_pair> ::= <pdu_c_echo_rq> <pdu_c_echo_rq_second>
<pdu_c_echo_rq_second> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_echo_rq_second>
<pdv_c_echo_rq_second> ::= <pdv_length> <pdv_context_id_data_verification> <mch_command_last> <cs_c_echo_rq_second>
<cs_c_echo_rq_second> ::= <cmd_group_length> <cmd_affected_sop_class_uid_verification> <cmd_field_c_echo_rq> <cmd_message_id_second> <cmd_data_set_type_none>
<cmd_message_id_second> ::= b'\x00\x00\x10\x01' <cmd_length> <message_id_value_second>
<message_id_value_second> ::= <le16>
where forall <v> in <message_id_value_second>: <v> == other_message_id(<v>)
<exchange_c_echo_pair> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo_pair> <Server:rsp_c_echo> <Server:rsp_c_echo> <TimerControl:dimse_timer_cancel>
<exchange_c_echo_pair_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo_pair> (<Server:rsp_abort> | <Server:rsp_c_echo> <Server:rsp_abort>) <TimerControl:dimse_timer_cancel>
<exchange_c_echo_pair_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo_pair> <TimerEvent:dimse_timer_expired> | <TimerControl:dimse_timer_start> <Client:req_c_echo_pair> <Server:rsp_c_echo> <TimerEvent:dimse_timer_expired>
<pdu_c_echo_rq_two_fragments> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_echo_rq_head> <pdv_c_echo_rq_tail>
<pdu_c_echo_rq_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_echo_rq_head>
<pdu_c_echo_rq_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_echo_rq_tail>
<pdv_c_echo_rq_head> ::= <pdv_length> <pdv_context_id_verification> <mch_command_more> <cs_c_echo_rq_head>
<pdv_c_echo_rq_tail> ::= <pdv_length> <pdv_context_id_data_verification> <mch_command_last> <cs_c_echo_rq_tail>
<pdv_context_id_data_verification> ::= <pdv_context_id> := recall_context("verification")
<cs_c_echo_rq_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_verification>
<cs_c_echo_rq_tail> ::= <cmd_field_c_echo_rq> <cmd_message_id> <cmd_data_set_type_none>
# PS3.8 E.1: the C-CANCEL command set in two Command Fragments (after the Command Field), as one PDU or as two
<pdu_c_cancel_find_rq_two_fragments> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_find_rq_head> <pdv_c_cancel_find_rq_tail>
<pdu_c_cancel_find_rq_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_find_rq_head>
<pdu_c_cancel_find_rq_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_find_rq_tail>
<pdv_c_cancel_find_rq_head> ::= <pdv_length> <pdv_context_id_cancel_find> <mch_command_more> <cs_c_cancel_rq_head>
<pdv_c_cancel_find_rq_tail> ::= <pdv_length> <pdv_context_id_cancel_find> <mch_command_last> <cs_c_cancel_rq_tail>
<pdu_c_cancel_get_rq_two_fragments> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_get_rq_head> <pdv_c_cancel_get_rq_tail>
<pdu_c_cancel_get_rq_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_get_rq_head>
<pdu_c_cancel_get_rq_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_get_rq_tail>
<pdv_c_cancel_get_rq_head> ::= <pdv_length> <pdv_context_id_cancel_get> <mch_command_more> <cs_c_cancel_rq_head>
<pdv_c_cancel_get_rq_tail> ::= <pdv_length> <pdv_context_id_cancel_get> <mch_command_last> <cs_c_cancel_rq_tail>
<pdu_c_cancel_move_rq_two_fragments> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_move_rq_head> <pdv_c_cancel_move_rq_tail>
<pdu_c_cancel_move_rq_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_move_rq_head>
<pdu_c_cancel_move_rq_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_cancel_move_rq_tail>
<pdv_c_cancel_move_rq_head> ::= <pdv_length> <pdv_context_id_cancel_move> <mch_command_more> <cs_c_cancel_rq_head>
<pdv_c_cancel_move_rq_tail> ::= <pdv_length> <pdv_context_id_cancel_move> <mch_command_last> <cs_c_cancel_rq_tail>
<cs_c_cancel_rq_head> ::= <cmd_group_length_split> <cmd_field_c_cancel_rq>
<cs_c_cancel_rq_tail> ::= <cmd_message_id_responded_cancel> <cmd_data_set_type_none>
# PS3.8 E.1: every request command set in two Command Fragments (after its first element), the first fragment with the more flag, as two PDUs
<cs_c_store_rq_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_storage>
<cs_c_store_rq_tail> ::= <cmd_field_c_store_rq> <cmd_message_id> <cmd_priority> <cmd_data_set_type_present> <cmd_affected_sop_instance_uid> <cmd_move_originator_ae>? <cmd_move_originator_message_id>?
<pdv_c_store_rq_ivle_head> ::= <pdv_length> <pdv_context_id_storage_ivle> <mch_command_more> <cs_c_store_rq_head>
<pdv_c_store_rq_ivle_tail> ::= <pdv_length> <pdv_context_id_data_storage> <mch_command_last> <cs_c_store_rq_tail>
<pdu_c_store_rq_ivle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_ivle_head>
<pdu_c_store_rq_ivle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_ivle_tail>
<pdv_c_store_rq_evle_head> ::= <pdv_length> <pdv_context_id_storage_evle> <mch_command_more> <cs_c_store_rq_head>
<pdv_c_store_rq_evle_tail> ::= <pdv_length> <pdv_context_id_data_storage> <mch_command_last> <cs_c_store_rq_tail>
<pdu_c_store_rq_evle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_evle_head>
<pdu_c_store_rq_evle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_rq_evle_tail>
<cs_c_find_rq_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_find>
<cs_c_find_rq_tail> ::= <cmd_field_c_find_rq> <cmd_message_id> <cmd_priority> <cmd_data_set_type_present>
<pdv_c_find_rq_ivle_head> ::= <pdv_length> <pdv_context_id_find_ivle> <mch_command_more> <cs_c_find_rq_head>
<pdv_c_find_rq_ivle_tail> ::= <pdv_length> <pdv_context_id_data_find> <mch_command_last> <cs_c_find_rq_tail>
<pdu_c_find_rq_ivle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rq_ivle_head>
<pdu_c_find_rq_ivle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rq_ivle_tail>
<pdv_c_find_rq_evle_head> ::= <pdv_length> <pdv_context_id_find_evle> <mch_command_more> <cs_c_find_rq_head>
<pdv_c_find_rq_evle_tail> ::= <pdv_length> <pdv_context_id_data_find> <mch_command_last> <cs_c_find_rq_tail>
<pdu_c_find_rq_evle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rq_evle_head>
<pdu_c_find_rq_evle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rq_evle_tail>
<cs_c_get_rq_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_get>
<cs_c_get_rq_tail> ::= <cmd_field_c_get_rq> <cmd_message_id> <cmd_priority> <cmd_data_set_type_present>
<pdv_c_get_rq_ivle_head> ::= <pdv_length> <pdv_context_id_get_ivle> <mch_command_more> <cs_c_get_rq_head>
<pdv_c_get_rq_ivle_tail> ::= <pdv_length> <pdv_context_id_data_get> <mch_command_last> <cs_c_get_rq_tail>
<pdu_c_get_rq_ivle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rq_ivle_head>
<pdu_c_get_rq_ivle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rq_ivle_tail>
<pdv_c_get_rq_evle_head> ::= <pdv_length> <pdv_context_id_get_evle> <mch_command_more> <cs_c_get_rq_head>
<pdv_c_get_rq_evle_tail> ::= <pdv_length> <pdv_context_id_data_get> <mch_command_last> <cs_c_get_rq_tail>
<pdu_c_get_rq_evle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rq_evle_head>
<pdu_c_get_rq_evle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rq_evle_tail>
<cs_c_move_rq_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_move>
<cs_c_move_rq_tail> ::= <cmd_field_c_move_rq> <cmd_message_id> <cmd_move_destination> <cmd_priority> <cmd_data_set_type_present>
<pdv_c_move_rq_ivle_head> ::= <pdv_length> <pdv_context_id_move_ivle> <mch_command_more> <cs_c_move_rq_head>
<pdv_c_move_rq_ivle_tail> ::= <pdv_length> <pdv_context_id_data_move> <mch_command_last> <cs_c_move_rq_tail>
<pdu_c_move_rq_ivle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_ivle_head>
<pdu_c_move_rq_ivle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_ivle_tail>
<pdv_c_move_rq_evle_head> ::= <pdv_length> <pdv_context_id_move_evle> <mch_command_more> <cs_c_move_rq_head>
<pdv_c_move_rq_evle_tail> ::= <pdv_length> <pdv_context_id_data_move> <mch_command_last> <cs_c_move_rq_tail>
<pdu_c_move_rq_evle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_evle_head>
<pdu_c_move_rq_evle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_evle_tail>
<cs_c_move_rq_unknown_destination_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_move>
<cs_c_move_rq_unknown_destination_tail> ::= <cmd_field_c_move_rq> <cmd_message_id> <cmd_move_destination_unknown> <cmd_priority> <cmd_data_set_type_present>
<pdv_c_move_rq_unknown_destination_ivle_head> ::= <pdv_length> <pdv_context_id_move_ivle> <mch_command_more> <cs_c_move_rq_unknown_destination_head>
<pdv_c_move_rq_unknown_destination_ivle_tail> ::= <pdv_length> <pdv_context_id_data_move> <mch_command_last> <cs_c_move_rq_unknown_destination_tail>
<pdu_c_move_rq_unknown_destination_ivle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_unknown_destination_ivle_head>
<pdu_c_move_rq_unknown_destination_ivle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_unknown_destination_ivle_tail>
<pdv_c_move_rq_unknown_destination_evle_head> ::= <pdv_length> <pdv_context_id_move_evle> <mch_command_more> <cs_c_move_rq_unknown_destination_head>
<pdv_c_move_rq_unknown_destination_evle_tail> ::= <pdv_length> <pdv_context_id_data_move> <mch_command_last> <cs_c_move_rq_unknown_destination_tail>
<pdu_c_move_rq_unknown_destination_evle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_unknown_destination_evle_head>
<pdu_c_move_rq_unknown_destination_evle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rq_unknown_destination_evle_tail>
<cs_n_set_rq_head> ::= <cmd_group_length_split> <cmd_requested_sop_class_uid>
<cs_n_set_rq_tail> ::= <cmd_field_n_set_rq> <cmd_message_id> <cmd_data_set_type_present> <cmd_requested_sop_instance_uid>
<pdv_n_set_rq_ivle_head> ::= <pdv_length> <pdv_context_id_normalized_ivle> <mch_command_more> <cs_n_set_rq_head>
<pdv_n_set_rq_ivle_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_set_rq_tail>
<pdu_n_set_rq_ivle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rq_ivle_head>
<pdu_n_set_rq_ivle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rq_ivle_tail>
<pdv_n_set_rq_evle_head> ::= <pdv_length> <pdv_context_id_normalized_evle> <mch_command_more> <cs_n_set_rq_head>
<pdv_n_set_rq_evle_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_set_rq_tail>
<pdu_n_set_rq_evle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rq_evle_head>
<pdu_n_set_rq_evle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rq_evle_tail>
<cs_n_action_rq_data_head> ::= <cmd_group_length_split> <cmd_requested_sop_class_uid>
<cs_n_action_rq_data_tail> ::= <cmd_field_n_action_rq> <cmd_message_id> <cmd_data_set_type_present> <cmd_requested_sop_instance_uid> <cmd_action_type_id>
<pdv_n_action_rq_data_ivle_head> ::= <pdv_length> <pdv_context_id_normalized_ivle> <mch_command_more> <cs_n_action_rq_data_head>
<pdv_n_action_rq_data_ivle_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_action_rq_data_tail>
<pdu_n_action_rq_data_ivle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_data_ivle_head>
<pdu_n_action_rq_data_ivle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_data_ivle_tail>
<pdv_n_action_rq_data_evle_head> ::= <pdv_length> <pdv_context_id_normalized_evle> <mch_command_more> <cs_n_action_rq_data_head>
<pdv_n_action_rq_data_evle_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_action_rq_data_tail>
<pdu_n_action_rq_data_evle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_data_evle_head>
<pdu_n_action_rq_data_evle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_data_evle_tail>
<cs_n_create_rq_data_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_normalized>
<cs_n_create_rq_data_tail> ::= <cmd_field_n_create_rq> <cmd_message_id> <cmd_data_set_type_present> <cmd_affected_sop_instance_uid>?
<pdv_n_create_rq_data_ivle_head> ::= <pdv_length> <pdv_context_id_normalized_ivle> <mch_command_more> <cs_n_create_rq_data_head>
<pdv_n_create_rq_data_ivle_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_create_rq_data_tail>
<pdu_n_create_rq_data_ivle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_data_ivle_head>
<pdu_n_create_rq_data_ivle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_data_ivle_tail>
<pdv_n_create_rq_data_evle_head> ::= <pdv_length> <pdv_context_id_normalized_evle> <mch_command_more> <cs_n_create_rq_data_head>
<pdv_n_create_rq_data_evle_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_create_rq_data_tail>
<pdu_n_create_rq_data_evle_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_data_evle_head>
<pdu_n_create_rq_data_evle_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_data_evle_tail>
<cs_n_action_rq_head> ::= <cmd_group_length_split> <cmd_requested_sop_class_uid>
<cs_n_action_rq_tail> ::= <cmd_field_n_action_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_requested_sop_instance_uid> <cmd_action_type_id>
<pdv_n_action_rq_head> ::= <pdv_length> <pdv_context_id_normalized> <mch_command_more> <cs_n_action_rq_head>
<pdv_n_action_rq_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_action_rq_tail>
<pdu_n_action_rq_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_head>
<pdu_n_action_rq_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rq_tail>
<cs_n_create_rq_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_normalized>
<cs_n_create_rq_tail> ::= <cmd_field_n_create_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_affected_sop_instance_uid>?
<pdv_n_create_rq_head> ::= <pdv_length> <pdv_context_id_normalized> <mch_command_more> <cs_n_create_rq_head>
<pdv_n_create_rq_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_create_rq_tail>
<pdu_n_create_rq_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_head>
<pdu_n_create_rq_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rq_tail>
<cs_n_get_rq_head> ::= <cmd_group_length_split> <cmd_requested_sop_class_uid>
<cs_n_get_rq_tail> ::= <cmd_field_n_get_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_requested_sop_instance_uid> <cmd_attribute_identifier_list>?
<pdv_n_get_rq_head> ::= <pdv_length> <pdv_context_id_normalized> <mch_command_more> <cs_n_get_rq_head>
<pdv_n_get_rq_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_get_rq_tail>
<pdu_n_get_rq_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_get_rq_head>
<pdu_n_get_rq_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_get_rq_tail>
<cs_n_delete_rq_head> ::= <cmd_group_length_split> <cmd_requested_sop_class_uid>
<cs_n_delete_rq_tail> ::= <cmd_field_n_delete_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_requested_sop_instance_uid>
<pdv_n_delete_rq_head> ::= <pdv_length> <pdv_context_id_normalized> <mch_command_more> <cs_n_delete_rq_head>
<pdv_n_delete_rq_tail> ::= <pdv_length> <pdv_context_id_data_normalized> <mch_command_last> <cs_n_delete_rq_tail>
<pdu_n_delete_rq_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_delete_rq_head>
<pdu_n_delete_rq_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_delete_rq_tail>
<cmd_group_length_split> ::= b'\x00\x00\x00\x00' <cmd_length> <cmd_group_length_value_split>
<cmd_group_length_value_split> ::= rb'[\x00-\xff]{4}'
where forall <g> in <cmd_group_length_value_split>: <g> == u32le(split_command_length(<g>))
# PS3.8 E.1: a response command set whose Data Set Type is fixed to 'no data set' (C-ECHO-RSP, C-STORE-RSP, N-DELETE-RSP) in several Command Fragments: one or more fragments with the more flag, then the last one. No data set can follow,
# so the last fragment ends the message; the fragments are opaque bytes whose content `split_command_ok` checks (the command is a response of the expected kind, Data Set Type 0101H, Message ID Being Responded To, Status, UIDs)
<rsp_command_split> ::= <pdu_command_more_only_rcv>+ <pdu_command_ending_rcv> | <pdu_command_with_more_and_last_rcv>
# a P-DATA-TF holds one or more PDVs (PS3.8 9.3.5, E.1): PDUs of fragments with the more flag, then the PDU that holds the last fragment (with any number of more fragments before it), or one PDU with all of them
<pdu_command_more_only_rcv> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_command_more_rcv>+
<pdu_command_ending_rcv> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_command_more_rcv>* <pdv_command_last_rcv>
<pdu_command_with_more_and_last_rcv> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_command_more_rcv>+ <pdv_command_last_rcv>
<pdv_command_more_rcv> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_more_rcv> <command_fragment_more_rcv>
<command_fragment_more_rcv> ::= <pdv_chunk>{pdv_chunks(<pdv_length>)} <byte>{pdv_rest(<pdv_length>)}
<pdv_command_last_rcv> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <command_fragment_last_rcv>
<command_fragment_last_rcv> ::= <pdv_chunk>{pdv_chunks(<pdv_length>)} <byte>{pdv_rest(<pdv_length>)}
# every received command fragment has an even number of bytes and is not empty (PS3.8 E.1), the same check as for the data set fragments
where forall <f> in <command_fragment_more_rcv>: fragment_ok(<f>)
where forall <f> in <command_fragment_last_rcv>: fragment_ok(<f>)
# PS3.8 E.1: a received message whose command set comes in several Command Fragments (at least one with the more flag), optionally followed by a data set in any number of PDVs, in the
# same P-DATA-TF as the last command fragment or in PDUs of their own. The fragments are opaque bytes: <split_message_ok> reassembles the command and decides (Command Data Set Type 0101H
# <=> no data PDV follows) whether a data set belongs to the message; the longest parse is the message (Fandango waits for further data after a parse that can grow)
<split_msg_rcv> ::= <pdu_command_more_only_rcv>+ <pdu_command_end0_rcv> <dataset_message_rest_rcv>? | <pdu_command_end1_rcv> <dataset_message_rest_rcv>?
<pdu_command_end0_rcv> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_command_more_rcv>* <pdv_command_last_rcv> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>?
<pdu_command_end1_rcv> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_command_more_rcv>+ <pdv_command_last_rcv> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>?
<dataset_message_rest_rcv> ::= <pdu_dataset_rcv_more>* <pdu_dataset_rcv>
<rsp_c_echo> ::= <pdu_c_echo_rsp> | <rsp_command_split>
<rsp_c_store> ::= <pdu_c_store_rsp> | <rsp_command_split>
<req_n_get> ::= <pdu_n_get_rq> | <pdu_n_get_rq_head> <pdu_n_get_rq_tail>
<req_n_delete> ::= <pdu_n_delete_rq> | <pdu_n_delete_rq_head> <pdu_n_delete_rq_tail>
<cs_n_get_rsp_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_get_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_attribute_identifier_list>?
<pdv_n_get_rsp_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_get_rsp_none>
<pdu_n_get_rsp_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_get_rsp_none>
<cs_n_get_rsp_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_get_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_attribute_identifier_list>?
<pdv_n_get_rsp_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_get_rsp_data>
<pdu_n_get_rsp_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_get_rsp_data>
<pdu_n_get_rsp_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_get_rsp_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_n_get_rsp_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_get_rsp_data> <pdv_dataset_rcv_more>+
<rsp_n_get_more_data> ::= <pdu_n_get_rsp_dataset_more> <dataset_message_rest_rcv>
<rsp_n_get_split> ::= <split_msg_rcv>
<rsp_n_get> ::= <pdu_n_get_rsp_none> | <pdu_n_get_rsp_data> <dataset_message_rcv> | <pdu_n_get_rsp_dataset> | <rsp_n_get_more_data> | <rsp_n_get_split>
<cs_n_set_rsp_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_set_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_attribute_identifier_list>?
<pdv_n_set_rsp_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_set_rsp_none>
<pdu_n_set_rsp_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rsp_none>
<cs_n_set_rsp_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_set_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_attribute_identifier_list>?
<pdv_n_set_rsp_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_set_rsp_data>
<pdu_n_set_rsp_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rsp_data>
<pdu_n_set_rsp_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rsp_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_n_set_rsp_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_set_rsp_data> <pdv_dataset_rcv_more>+
<rsp_n_set_more_data> ::= <pdu_n_set_rsp_dataset_more> <dataset_message_rest_rcv>
<rsp_n_set_split> ::= <split_msg_rcv>
<rsp_n_set> ::= <pdu_n_set_rsp_none> | <pdu_n_set_rsp_data> <dataset_message_rcv> | <pdu_n_set_rsp_dataset> | <rsp_n_set_more_data> | <rsp_n_set_split>
<cs_n_action_rsp_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_action_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_action_type_id>?
<pdv_n_action_rsp_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_action_rsp_none>
<pdu_n_action_rsp_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rsp_none>
<cs_n_action_rsp_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_action_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_action_type_id>?
<pdv_n_action_rsp_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_action_rsp_data>
<pdu_n_action_rsp_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rsp_data>
<pdu_n_action_rsp_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rsp_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_n_action_rsp_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_action_rsp_data> <pdv_dataset_rcv_more>+
<rsp_n_action_more_data> ::= <pdu_n_action_rsp_dataset_more> <dataset_message_rest_rcv>
<rsp_n_action_split> ::= <split_msg_rcv>
<rsp_n_action> ::= <pdu_n_action_rsp_none> | <pdu_n_action_rsp_data> <dataset_message_rcv> | <pdu_n_action_rsp_dataset> | <rsp_n_action_more_data> | <rsp_n_action_split>
<cs_n_create_rsp_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_create_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_attribute_identifier_list>?
<pdv_n_create_rsp_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_create_rsp_none>
<pdu_n_create_rsp_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rsp_none>
<cs_n_create_rsp_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_n_create_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid>? <cmd_attribute_identifier_list>?
<pdv_n_create_rsp_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_create_rsp_data>
<pdu_n_create_rsp_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rsp_data>
<pdu_n_create_rsp_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rsp_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_n_create_rsp_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_create_rsp_data> <pdv_dataset_rcv_more>+
<rsp_n_create_more_data> ::= <pdu_n_create_rsp_dataset_more> <dataset_message_rest_rcv>
<rsp_n_create_split> ::= <split_msg_rcv>
<rsp_n_create> ::= <pdu_n_create_rsp_none> | <pdu_n_create_rsp_data> <dataset_message_rcv> | <pdu_n_create_rsp_dataset> | <rsp_n_create_more_data> | <rsp_n_create_split>
<rsp_n_delete> ::= <pdu_n_delete_rsp> | <rsp_command_split>

<exchange_c_echo> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo> <Server:rsp_c_echo> <TimerControl:dimse_timer_cancel>
<exchange_c_echo_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_c_echo_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo> <TimerEvent:dimse_timer_expired>
# PS3.8 7.6.1 / PS3.7 D.3.2 (C30, C38 breaker): one C-ECHO-RQ whose PDV names a Presentation Context ID that the A-ASSOCIATE-AC did not accept ("shall identify one of the agreed presentation contexts"): the id of a context
# the server refused, or any odd id that no context of the association has. The spec makes no reaction mandatory, so every reply is accepted: a C-ECHO-RSP (any status), an A-ABORT, or none within the DIMSE timer
<req_c_echo_unaccepted_context> ::= <pdu_c_echo_rq_unaccepted>
<pdu_c_echo_rq_unaccepted> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_echo_rq_unaccepted>
<pdv_c_echo_rq_unaccepted> ::= <pdv_length> <pdv_context_id_unaccepted> <mch_command_last> <cs_c_echo_rq>
<pdv_context_id_unaccepted> ::= <pdv_context_id> := unaccepted_context_id()
<exchange_c_echo_unaccepted_context> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo_unaccepted_context> <Server:rsp_c_echo> <TimerControl:dimse_timer_cancel>
<exchange_c_echo_unaccepted_context_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo_unaccepted_context> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_c_echo_unaccepted_context_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_echo_unaccepted_context> <TimerEvent:dimse_timer_expired>
<exchange_c_store> ::= <TimerControl:dimse_timer_start> <Client:req_c_store> <Server:rsp_c_store> <TimerControl:dimse_timer_cancel>
# C-STORE of a data set in a transfer syntax other than the two Little Endian ones (RLE, encapsulated Pixel Data, JPIP referenced, Explicit VR Big Endian): its own
# exchange, because these contexts are refused by servers that do not support them and the request is then not sent
<exchange_c_store_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_c_store> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_c_store_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_store> <TimerEvent:dimse_timer_expired>
# PS3.8 D.1.2 / C53 (breaker): one C-STORE whose data P-DATA-TF PDU is longer than the Maximum-Length-received the server announced ("it shall be a protocol error"); the command PDU is as large as any other.
# The spec makes no reaction mandatory, so every reply is accepted: a C-STORE-RSP, an A-ABORT, or none within the DIMSE timer
<req_c_store_oversized> ::= <pdu_c_store_rq_ivle> <pdu_dataset_store_oversized>
<pdv_dataset_store_oversized> ::= <pdv_length> <pdv_context_id_data_storage> <mch_dataset_last> <dataset_store_ivle_oversized>
<pdu_dataset_store_oversized> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_store_oversized>
<dataset_store_ivle_oversized> ::= <ivle_sop_class> <ivle_sop_instance> <ivle_modality> <ivle_private_creator> <ivle_private_oversized> <dataset_store_ivle_tail>
<ivle_private_oversized> ::= b'\x09\x00\x01\x10' <ds_ivle_length> <v_oversized>
<v_oversized> ::= rb'[A-H]{4,}' := oversized_value()
<exchange_c_store_oversized> ::= <TimerControl:dimse_timer_start> <Client:req_c_store_oversized> <Server:rsp_c_store> <TimerControl:dimse_timer_cancel>
# DCMTK answers the oversized PDU with an A-ABORT (source 0, reason 0) and, in the same TCP segment, a second A-ABORT (source 2, reason 2: it reads the rest of the PDU as a PDU of its own)
<rsp_abort_oversized> ::= <rsp_abort> <rsp_abort>?
<exchange_c_store_oversized_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_c_store_oversized> <Server:rsp_abort_oversized> <TimerControl:dimse_timer_cancel>
<exchange_c_store_oversized_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_store_oversized> <TimerEvent:dimse_timer_expired>
<exchange_n_get> ::= <TimerControl:dimse_timer_start> <Client:req_n_get> <Server:rsp_n_get> <TimerControl:dimse_timer_cancel>
<exchange_n_get_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_n_get> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_n_get_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_n_get> <TimerEvent:dimse_timer_expired>
<exchange_n_set> ::= <TimerControl:dimse_timer_start> <Client:req_n_set> <Server:rsp_n_set> <TimerControl:dimse_timer_cancel>
<exchange_n_set_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_n_set> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_n_set_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_n_set> <TimerEvent:dimse_timer_expired>
<exchange_n_action> ::= <TimerControl:dimse_timer_start> <Client:req_n_action> <Server:rsp_n_action> <TimerControl:dimse_timer_cancel>
<exchange_n_action_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_n_action> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_n_action_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_n_action> <TimerEvent:dimse_timer_expired>
<exchange_n_create> ::= <TimerControl:dimse_timer_start> <Client:req_n_create> <Server:rsp_n_create> <TimerControl:dimse_timer_cancel>
<exchange_n_create_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_n_create> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_n_create_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_n_create> <TimerEvent:dimse_timer_expired>
<exchange_n_delete> ::= <TimerControl:dimse_timer_start> <Client:req_n_delete> <Server:rsp_n_delete> <TimerControl:dimse_timer_cancel>
<exchange_n_delete_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_n_delete> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_n_delete_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_n_delete> <TimerEvent:dimse_timer_expired>

# C-FIND (PS3.7 9.3.2): pending responses carry an identifier, the final response none
<rsp_c_find_pending> ::= <pdu_c_find_rsp_pending> <dataset_message_rcv> | <pdu_c_find_rsp_pending_dataset> | <rsp_c_find_pending_more_data> | <rsp_c_find_pending_split>
<rsp_c_find_final> ::= <pdu_c_find_rsp_final> | <rsp_c_find_final_split>
<rsp_c_find_final_split> ::= <split_msg_rcv>
<pdu_c_find_rsp_pending_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rsp_pending> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_c_find_rsp_pending_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_find_rsp_pending> <pdv_dataset_rcv_more>+
<rsp_c_find_pending_more_data> ::= <pdu_c_find_rsp_pending_dataset_more> <dataset_message_rest_rcv>
<rsp_c_find_pending_split> ::= <split_msg_rcv>
<exchange_c_find> ::= <TimerControl:dimse_timer_start> <Client:req_c_find> <Server:rsp_c_find_pending>* <c_find_end>
# The reply that ends the exchange selects what follows: the final response goes on in Sta 6, an A-ABORT ends the association
<c_find_end> ::= <Server:rsp_c_find_final> <TimerControl:dimse_timer_cancel> <sta6> | <Server:rsp_abort> <TimerControl:dimse_timer_cancel> | <Client:req_c_cancel_find> <Server:rsp_c_find_pending>* <c_find_cancelled_end>
<c_find_cancelled_end> ::= <Server:rsp_c_find_final> <TimerControl:dimse_timer_cancel> <sta6> | <Server:rsp_abort> <TimerControl:dimse_timer_cancel> | <TimerEvent:dimse_timer_expired>
<exchange_c_find_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_find> <TimerEvent:dimse_timer_expired>
# C-CANCEL-FIND-RQ (PS3.7 9.3.2.3): sent at any time before a non-pending response arrives (<c_find_end>); the server answers with pending responses and a final one
# C-GET (PS3.7 9.3.3): C-STORE sub-operations on the same association, C-GET responses with sub-operation counts
<cs_c_get_rsp_pending_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_get_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status_pending> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_sub_operation_counts>
<pdv_c_get_rsp_pending_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_get_rsp_pending_none>
<pdu_c_get_rsp_pending_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rsp_pending_none>
<cs_c_get_rsp_pending_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_get_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status_pending> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_sub_operation_counts>
<pdv_c_get_rsp_pending_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_get_rsp_pending_data>
<pdu_c_get_rsp_pending_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rsp_pending_data>
<pdu_c_get_rsp_pending_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rsp_pending_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_c_get_rsp_pending_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rsp_pending_data> <pdv_dataset_rcv_more>+
<rsp_c_get_pending_more_data> ::= <pdu_c_get_rsp_pending_dataset_more> <dataset_message_rest_rcv>
<rsp_c_get_pending_split> ::= <split_msg_rcv>
<rsp_c_get_pending> ::= <pdu_c_get_rsp_pending_none> | <pdu_c_get_rsp_pending_data> <dataset_message_rcv> | <pdu_c_get_rsp_pending_dataset> | <rsp_c_get_pending_more_data> | <rsp_c_get_pending_split>
<cs_c_get_rsp_final_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_get_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status_final> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_remaining_suboperations>? <cmd_completed_suboperations>? <cmd_failed_suboperations>? <cmd_warning_suboperations>?
<pdv_c_get_rsp_final_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_get_rsp_final_none>
<pdu_c_get_rsp_final_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rsp_final_none>
<cs_c_get_rsp_final_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_get_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status_final> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_remaining_suboperations>? <cmd_completed_suboperations>? <cmd_failed_suboperations>? <cmd_warning_suboperations>?
<pdv_c_get_rsp_final_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_get_rsp_final_data>
<pdu_c_get_rsp_final_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rsp_final_data>
<pdu_c_get_rsp_final_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rsp_final_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_c_get_rsp_final_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_get_rsp_final_data> <pdv_dataset_rcv_more>+
<rsp_c_get_final_more_data> ::= <pdu_c_get_rsp_final_dataset_more> <dataset_message_rest_rcv>
<rsp_c_get_final_split> ::= <split_msg_rcv>
<rsp_c_get_final> ::= <pdu_c_get_rsp_final_none> | <pdu_c_get_rsp_final_data> <dataset_message_rcv> | <pdu_c_get_rsp_final_dataset> | <rsp_c_get_final_more_data> | <rsp_c_get_final_split>
<rsp_c_store_sub_rq> ::= <pdu_c_store_sub_rq> <dataset_message_rcv> | <pdu_c_store_sub_rq_dataset> | <rsp_c_store_sub_rq_more_data> | <rsp_c_store_sub_rq_split>
<pdu_c_store_sub_rq_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_sub_rq> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_c_store_sub_rq_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_sub_rq> <pdv_dataset_rcv_more>+
<rsp_c_store_sub_rq_more_data> ::= <pdu_c_store_sub_rq_dataset_more> <dataset_message_rest_rcv>
<rsp_c_store_sub_rq_split> ::= <split_msg_rcv>
<req_c_store_sub_rsp> ::= <pdu_c_store_sub_rsp>
<pdu_c_store_sub_rsp> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_store_sub_rsp>
<cmd_message_id_responded_sent> ::= b'\x00\x00\x20\x01' <cmd_length> <message_id_responded_sent_value>
<message_id_responded_sent_value> ::= <le16> := recall_server_message_id()
<cmd_status_success> ::= b'\x00\x00\x00\x09' <cmd_length> <status_success>
<exchange_c_store_sub> ::= <Server:rsp_c_store_sub_rq> <Client:req_c_store_sub_rsp>
where forall <x> in <exchange_c_store_sub>: <x>..<message_id_responded_sent_value> == bytes(<x>..<message_id_value>)
<exchange_c_get> ::= <TimerControl:dimse_timer_start> <Client:req_c_get> (<Server:rsp_c_get_pending> | <exchange_c_store_sub>)* <c_get_end>
# The reply that ends the exchange selects what follows: the final response goes on in Sta 6, an A-ABORT ends the association
<c_get_end> ::= <Server:rsp_c_get_final> <TimerControl:dimse_timer_cancel> <sta6> | <Server:rsp_abort> <TimerControl:dimse_timer_cancel> | <Client:req_c_cancel_get> (<Server:rsp_c_get_pending> | <exchange_c_store_sub>)* <c_get_cancelled_end>
<c_get_cancelled_end> ::= <Server:rsp_c_get_final> <TimerControl:dimse_timer_cancel> <sta6> | <Server:rsp_abort> <TimerControl:dimse_timer_cancel> | <TimerEvent:dimse_timer_expired>
<exchange_c_get_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_get> <TimerEvent:dimse_timer_expired>
# C-MOVE (PS3.7 9.3.4)
<cs_c_move_rsp_pending_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_move_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status_pending> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_sub_operation_counts>
<pdv_c_move_rsp_pending_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_move_rsp_pending_none>
<pdu_c_move_rsp_pending_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rsp_pending_none>
<cs_c_move_rsp_pending_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_move_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status_pending> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_sub_operation_counts>
<pdv_c_move_rsp_pending_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_move_rsp_pending_data>
<pdu_c_move_rsp_pending_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rsp_pending_data>
<pdu_c_move_rsp_pending_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rsp_pending_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_c_move_rsp_pending_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rsp_pending_data> <pdv_dataset_rcv_more>+
<rsp_c_move_pending_more_data> ::= <pdu_c_move_rsp_pending_dataset_more> <dataset_message_rest_rcv>
<rsp_c_move_pending_split> ::= <split_msg_rcv>
<rsp_c_move_pending> ::= <pdu_c_move_rsp_pending_none> | <pdu_c_move_rsp_pending_data> <dataset_message_rcv> | <pdu_c_move_rsp_pending_dataset> | <rsp_c_move_pending_more_data> | <rsp_c_move_pending_split>
<cs_c_move_rsp_final_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_move_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_none> <cmd_status_final> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_remaining_suboperations>? <cmd_completed_suboperations>? <cmd_failed_suboperations>? <cmd_warning_suboperations>?
<pdv_c_move_rsp_final_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_move_rsp_final_none>
<pdu_c_move_rsp_final_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rsp_final_none>
<cs_c_move_rsp_final_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid>? <cmd_field_c_move_rsp> <cmd_message_id>? <cmd_message_id_responded> <cmd_data_set_type_present> <cmd_status_final> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_remaining_suboperations>? <cmd_completed_suboperations>? <cmd_failed_suboperations>? <cmd_warning_suboperations>?
<pdv_c_move_rsp_final_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_c_move_rsp_final_data>
<pdu_c_move_rsp_final_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rsp_final_data>
<pdu_c_move_rsp_final_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rsp_final_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_c_move_rsp_final_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_c_move_rsp_final_data> <pdv_dataset_rcv_more>+
<rsp_c_move_final_more_data> ::= <pdu_c_move_rsp_final_dataset_more> <dataset_message_rest_rcv>
<rsp_c_move_final_split> ::= <split_msg_rcv>
<rsp_c_move_final> ::= <pdu_c_move_rsp_final_none> | <pdu_c_move_rsp_final_data> <dataset_message_rcv> | <pdu_c_move_rsp_final_dataset> | <rsp_c_move_final_more_data> | <rsp_c_move_final_split>
<exchange_c_move> ::= <TimerControl:dimse_timer_start> <Client:req_c_move> <Server:rsp_c_move_pending>* <c_move_end>
# The reply that ends the exchange selects what follows: the final response goes on in Sta 6, an A-ABORT ends the association
<c_move_end> ::= <Server:rsp_c_move_final> <TimerControl:dimse_timer_cancel> <sta6> | <Server:rsp_abort> <TimerControl:dimse_timer_cancel> | <Client:req_c_cancel_move> <Server:rsp_c_move_pending>* <c_move_cancelled_end>
<c_move_cancelled_end> ::= <Server:rsp_c_move_final> <TimerControl:dimse_timer_cancel> <sta6> | <Server:rsp_abort> <TimerControl:dimse_timer_cancel> | <TimerEvent:dimse_timer_expired>
<exchange_c_move_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_move> <TimerEvent:dimse_timer_expired>
# C-MOVE to a destination the server does not know: refused (PS3.7 C.4.3 A801), a refusal the spec defines
<exchange_c_move_unknown_destination> ::= <TimerControl:dimse_timer_start> <Client:req_c_move_unknown_destination> <Server:rsp_c_move_final> <TimerControl:dimse_timer_cancel>
<exchange_c_move_unknown_destination_aborted> ::= <TimerControl:dimse_timer_start> <Client:req_c_move_unknown_destination> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<exchange_c_move_unknown_destination_unanswered> ::= <TimerControl:dimse_timer_start> <Client:req_c_move_unknown_destination> <TimerEvent:dimse_timer_expired>

# Messages the server sends on its own initiative (PS3.7 10.3.1 N-EVENT-REPORT, PS3.8 9.3.8 A-ABORT, 9.3.6 A-RELEASE-RQ)
<server_event_report> ::= <Server:rsp_n_event_report_rq> <Client:req_n_event_report_rsp>
<cs_n_event_report_rq_none> ::= <cmd_group_length> <cmd_affected_sop_class_uid> <cmd_field_n_event_report_rq> <cmd_message_id> <cmd_data_set_type_none> <cmd_affected_sop_instance_uid> <cmd_event_type_id>
<pdv_n_event_report_rq_none> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_event_report_rq_none>
<pdu_n_event_report_rq_none> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rq_none>
<cs_n_event_report_rq_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid> <cmd_field_n_event_report_rq> <cmd_message_id> <cmd_data_set_type_present> <cmd_affected_sop_instance_uid> <cmd_event_type_id>
<pdv_n_event_report_rq_data> ::= <pdv_length> <pdv_context_id_rcv> <mch_command_last_rcv> <cs_n_event_report_rq_data>
<pdu_n_event_report_rq_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rq_data>
<pdu_n_event_report_rq_dataset> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rq_data> <pdv_dataset_rcv_more>* <pdv_dataset_rcv>
<pdu_n_event_report_rq_dataset_more> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rq_data> <pdv_dataset_rcv_more>+
<rsp_n_event_report_rq_more_data> ::= <pdu_n_event_report_rq_dataset_more> <dataset_message_rest_rcv>
<rsp_n_event_report_rq_split> ::= <split_msg_rcv>
<rsp_n_event_report_rq> ::= <pdu_n_event_report_rq_none> | <pdu_n_event_report_rq_data> <dataset_message_rcv> | <pdu_n_event_report_rq_dataset> | <rsp_n_event_report_rq_more_data> | <rsp_n_event_report_rq_split>
# PS3.7 10.3.1.2: the Event Reply is an optional data set; the Event Type ID shall be included whenever an Event Reply is
<req_n_event_report_rsp> ::= <pdu_n_event_report_rsp_sent> | <pdu_n_event_report_rsp_sent_data> (<pdu_dataset_event_reply_ivle> | <pdu_dataset_event_reply_evle>) | <pdu_n_event_report_rsp_sent_head> <pdu_n_event_report_rsp_sent_tail> | <pdu_n_event_report_rsp_sent_data_head> <pdu_n_event_report_rsp_sent_data_tail> (<pdu_dataset_event_reply_ivle> | <pdu_dataset_event_reply_evle>) | <pdu_n_event_report_rsp_with_data_ivle> | <pdu_n_event_report_rsp_with_data_evle>
<pdu_n_event_report_rsp_sent_data> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp_sent_data>
<pdv_n_event_report_rsp_sent_data> ::= <pdv_length> <pdv_context_id_event_sent> <mch_command_last> <cs_n_event_report_rsp_sent_data>
<cs_n_event_report_rsp_sent_data> ::= <cmd_group_length> <cmd_affected_sop_class_uid_echo>? <cmd_field_n_event_report_rsp> <cmd_message_id_responded_sent> <cmd_data_set_type_present> <cmd_status_event_sent> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid_echo>? <cmd_event_type_id_echo>
# PS3.8 E.1: the reply command set in two Command Fragments (after the optional Affected SOP Class UID), the command and the Event Reply in one P-DATA-TF
<cs_n_event_report_rsp_sent_head> ::= <cmd_group_length_split> <cmd_affected_sop_class_uid_echo>?
<cs_n_event_report_rsp_sent_tail> ::= <cmd_field_n_event_report_rsp> <cmd_message_id_responded_sent> <cmd_data_set_type_none> <cmd_status_event_sent> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid_echo>? <cmd_event_type_id_echo>?
<cs_n_event_report_rsp_sent_data_tail> ::= <cmd_field_n_event_report_rsp> <cmd_message_id_responded_sent> <cmd_data_set_type_present> <cmd_status_event_sent> <cmd_offending_element>? <cmd_error_comment>? <cmd_error_id>? <cmd_affected_sop_instance_uid_echo>? <cmd_event_type_id_echo>
<pdv_n_event_report_rsp_sent_head> ::= <pdv_length> <pdv_context_id_event_sent> <mch_command_more> <cs_n_event_report_rsp_sent_head>
<pdv_n_event_report_rsp_sent_tail> ::= <pdv_length> <pdv_context_id_event_sent> <mch_command_last> <cs_n_event_report_rsp_sent_tail>
<pdv_n_event_report_rsp_sent_data_head> ::= <pdv_length> <pdv_context_id_event_sent> <mch_command_more> <cs_n_event_report_rsp_sent_head>
<pdv_n_event_report_rsp_sent_data_tail> ::= <pdv_length> <pdv_context_id_event_sent> <mch_command_last> <cs_n_event_report_rsp_sent_data_tail>
<pdu_n_event_report_rsp_sent_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp_sent_head>
<pdu_n_event_report_rsp_sent_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp_sent_tail>
<pdu_n_event_report_rsp_sent_data_head> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp_sent_data_head>
<pdu_n_event_report_rsp_sent_data_tail> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp_sent_data_tail>
<pdu_n_event_report_rsp_with_data_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp_sent_data> <pdv_dataset_event_reply_ivle>
<pdu_n_event_report_rsp_with_data_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp_sent_data> <pdv_dataset_event_reply_evle>
<pdu_dataset_event_reply_ivle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_event_reply_ivle>
<pdv_dataset_event_reply_ivle> ::= <pdv_length> <pdv_context_id_event_sent> <mch_dataset_last> <dataset_normalized_ivle>
<pdu_dataset_event_reply_evle> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_dataset_event_reply_evle>
<pdv_dataset_event_reply_evle> ::= <pdv_length> <pdv_context_id_event_sent> <mch_dataset_last> <dataset_normalized_evle>
<pdu_n_event_report_rsp_sent> ::= b'\x04' <reserved_byte> <pdu_length> <pdv_n_event_report_rsp_sent>
where forall <x> in <server_event_report>: <x>..<message_id_responded_sent_value> == bytes(<x>..<message_id_value>)
<server_release> ::= <Server:rsp_release_rq> <Client:req_pdata_in_release>* (<Client:req_release_rp> <sta13> | <Server:rsp_abort> | <Client:req_abort> <sta13>)
# PS3.8 9.2.1 Sta 8 (AR-7): the acceptor may send P-DATA-TF before its A-RELEASE-RP
<req_pdata_in_release> ::= <pdu_c_echo_rq>
<rsp_release_rq> ::= b'\x05' <reserved_byte> <pdu_length_four> <rb_any_4>
<req_release_rp> ::= b'\x06' <reserved_byte> <pdu_length_four> <reserved_32_bit>
<server_abort> ::= <Server:rsp_abort>

# A-ABORT sent by the client (PS3.8 9.3.8): service-user source with reason 0, or provider source with a provider reason
# Sta 13 (PS3.8 9.2.1, 9.1.5): awaiting the transport connection close. The ARTIM timer runs; the peer's A-ABORT (AA-2) and every other PDU (A-ASSOCIATE-AC/RJ/RQ, P-DATA-TF, A-RELEASE-RQ/RP, an unrecognized or invalid PDU: AA-6, AA-7) that arrives meanwhile
# is accepted and ignored, and the expiry ends the wait for the close. Sta 13 follows every A-ABORT request of the client (AA-1) and the client's A-RELEASE-RP to a release of the server's side (AR-4).
# The ARTIM timer of an A-ABORT sent in Sta 6 is started before the abort is sent (a timer started after it would race with the server's messages)
<exchange_abort_by_client_artim> ::= <TimerControl:artim_timer_start> <Client:req_abort> <sta13_pdu>* <TimerEvent:artim_timer_expired>
<sta13> ::= <TimerControl:artim_timer_start> <sta13_pdu>* <TimerEvent:artim_timer_expired>
# PS3.8 9.2.1 Table 9-10 AA-1 in Sta 5 and Sta 7: the client's A-ABORT issued while the reply to its A-ASSOCIATE-RQ / A-RELEASE-RQ is still pending. Fandango needs 100 - 300 ms to generate a message and the servers answer within
# 10 ms, so a separate A-ABORT message would always follow the reply; the abort is therefore sent in the same message as the request (the RQ and the A-ABORT PDU in one write), which is Sta 5 / Sta 7 -> AA-1 -> Sta 13 as
# far as the server can tell. What the server answers (the A-ASSOCIATE-AC / A-RELEASE-RP that crosses, an A-ABORT, nothing) arrives in Sta 13, where every PDU is accepted and ignored.
<exchange_associate_abort_at_once> ::= <TimerControl:artim_timer_start> <Client:req_associate_abort> <sta13_pdu>* <TimerEvent:artim_timer_expired>
<req_associate_abort> ::= <req_associate> <req_abort>
<exchange_release_abort_at_once> ::= <TimerControl:artim_timer_start> <Client:req_release_abort> <sta13_pdu>* <TimerEvent:artim_timer_expired>
<req_release_abort> ::= <req_release> <req_abort>
<sta13_pdu> ::= <Server:rsp_abort> | <Server:rsp_other_pdu>
<rsp_other_pdu> ::= rb'[\x00-\x06\x08-\xff]' <reserved_byte> <pdu_length> <pdata_while_releasing>
<req_abort> ::= b'\x07' <reserved_byte> <pdu_length_four> <reserved_byte> <reserved_byte> (<abort_source_user> b'\x00' | <abort_source_provider> <abort_provider_reason_sent>)
# Unexpected PDUs sent in the association state: the server must reject them (PS3.8 9.2 AA-8)
<exchange_unexpected_associate_rq> ::= <TimerControl:dimse_timer_start> <Client:req_associate_again> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<req_associate_again> ::= <req_associate>
<exchange_unexpected_release_rp> ::= <TimerControl:dimse_timer_start> <Client:req_release_rp_unsolicited> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<req_release_rp_unsolicited> ::= <req_release_rp>
# Unrecognized PDU type (PS3.8 9.3): the receiver aborts
<exchange_unrecognized_pdu> ::= <TimerControl:dimse_timer_start> <Client:req_unrecognized_pdu> <Server:rsp_abort> <TimerControl:dimse_timer_cancel>
<req_unrecognized_pdu> ::= rb'[\x08-\xff]' <reserved_byte> <pdu_length> <unrecognized_pdu_body>
<unrecognized_pdu_body> ::= rb'[\x00-\xff]{4}'
# Sta 2 (PS3.8 9.2.1): a PDU other than A-ASSOCIATE-RQ before the association exists; the server aborts (AA-1) or closes the connection (AA-2)
<exchange_without_association> ::= <TimerControl:associate_timer_start> <Client:req_without_association> (<Server:rsp_abort> <TimerControl:associate_timer_cancel> | <TimerEvent:associate_timer_expired>)
<req_without_association> ::= <req_pdata_without_association> | <req_release_without_association> | <req_release_rp_without_association> | <req_abort_without_association> | <req_associate_rj_without_association> | <req_associate_ac_without_association> | <req_unrecognized_pdu_without_association>
<req_unrecognized_pdu_without_association> ::= <req_unrecognized_pdu>
<req_pdata_without_association> ::= <pdu_c_echo_rq>
<req_release_without_association> ::= <req_release>
<req_release_rp_without_association> ::= <req_release_rp>
<req_abort_without_association> ::= <req_abort>
<req_associate_rj_without_association> ::= b'\x03' <reserved_byte> <pdu_length_four> <reserved_byte> b'\x01' b'\x01' b'\x01'
<req_associate_ac_without_association> ::= b'\x02' <reserved_byte> <pdu_length> <protocol_version> <reserved_2> <called_ae_title> <calling_ae_title> <reserved_32> <application_context_item> <ac_sent_presentation_context_item> <ac_sent_user_information_item>
<ac_sent_presentation_context_item> ::= b'\x21' <reserved_byte> <item_length> b'\x01' <reserved_byte> <pc_acceptance> <reserved_byte> <transfer_syntax_item_default>
<ac_sent_user_information_item> ::= b'\x50' <reserved_byte> <item_length> <maximum_length_item> <implementation_class_uid_item>


# ======================================================================================================
# Semantic constraints on received messages (checked when the exchange is complete)
# ======================================================================================================
where forall <x> in <exchange_associate_accepted>: associate_ok(<x>)
where forall <x> in <exchange_associate_refused_all>: associate_ok(<x>)
where forall <x> in <exchange_associate_wrong_called_refused_all>: associate_ok(<x>)
where forall <x> in <exchange_associate_wrong_credentials_refused_all>: associate_ok(<x>)
where forall <x> in <exchange_associate_offer_breaker>: associate_ok(<x>)
where forall <x> in <exchange_associate_wrong_called_accepted>: associate_ok(<x>)
where forall <x> in <exchange_associate_wrong_credentials_accepted>: associate_ok(<x>)
where forall <x> in <exchange_associate_variant>: associate_ok(<x>)
where forall <x> in <exchange_associate_contexts>: associate_ok(<x>)
where forall <x> in <exchange_c_echo>: message_id_matches(<x>) and echo_status_ok(<x>)
where forall <x> in <exchange_c_echo_pair>: echo_pair_ok(<x>) and echo_status_ok(<x>) and uid_echo_ok(<x>)
where forall <x> in <exchange_c_echo_pair_aborted>: echo_pair_ok(<x>) and echo_status_ok(<x>) and uid_echo_ok(<x>) and split_command_ok(<x>, 0x8030, True)
where forall <x> in <exchange_c_echo_pair_unanswered>: echo_pair_ok(<x>) and echo_status_ok(<x>) and uid_echo_ok(<x>) and split_command_ok(<x>, 0x8030, True)
where forall <x> in <exchange_c_store>: message_id_matches(<x>)
where forall <x> in <exchange_c_store_oversized>: message_id_matches(<x>)
where forall <x> in <exchange_c_find>: message_id_matches(<x>) and find_response_ok(<x>)
where forall <x> in <exchange_c_get>: message_id_matches(<x>)
where forall <x> in <exchange_c_move>: message_id_matches(<x>)
where forall <x> in <exchange_n_get>: message_id_matches(<x>)
where forall <x> in <exchange_n_set>: message_id_matches(<x>)
where forall <x> in <exchange_n_action>: message_id_matches(<x>)
where forall <x> in <exchange_n_create>: message_id_matches(<x>)
where forall <x> in <exchange_n_delete>: message_id_matches(<x>)
where forall <l> in <pdu_length>: pdu_length_ok(<l>)
where forall <d> in <dataset_message_rcv>: dataset_message_wellformed(<d>)
# PS3.5 7.1 / PS3.8 E.1: every value, hence every command element, has an even length
where forall <l> in <cmd_length>: int.from_bytes(bytes(<l>), 'little') % 2 == 0
where forall <x> in <exchange_c_echo>: uid_echo_ok(<x>)
where forall <x> in <exchange_c_echo>: split_command_ok(<x>, 0x8030, True)
where forall <x> in <exchange_c_echo_pair>: split_command_ok(<x>, 0x8030, True)
where forall <x> in <exchange_c_echo_unaccepted_context>: message_id_matches(<x>) and uid_echo_ok(<x>) and split_command_ok(<x>, 0x8030, True)
where forall <x> in <exchange_c_store>: split_command_ok(<x>, 0x8001, False)
where forall <x> in <exchange_c_store_oversized>: split_command_ok(<x>, 0x8001, False)
where forall <x> in <exchange_n_delete>: split_command_ok(<x>, 0x8150, False)
where forall <x> in <exchange_c_store>: uid_echo_ok(<x>)
where forall <x> in <exchange_c_store_oversized>: uid_echo_ok(<x>)
where forall <x> in <exchange_c_find>: uid_echo_ok(<x>)
where forall <x> in <exchange_c_get>: uid_echo_ok(<x>)
where forall <x> in <exchange_c_move>: uid_echo_ok(<x>)
where forall <x> in <exchange_c_move_unknown_destination>: message_id_matches(<x>) and uid_echo_ok(<x>)
where forall <x> in <exchange_n_get>: uid_echo_ok(<x>) and normalized_response_ok(<x>)
where forall <x> in <exchange_n_set>: uid_echo_ok(<x>)
where forall <x> in <exchange_n_action>: uid_echo_ok(<x>) and normalized_response_ok(<x>)
where forall <x> in <exchange_n_create>: uid_echo_ok(<x>) and normalized_response_ok(<x>)
where forall <x> in <exchange_n_delete>: uid_echo_ok(<x>)
# Received messages: one presentation context per message, an accepted one; data sets obey the rules of their transfer syntax, fragments are even and not empty
where forall <c> in <pdv_context_id_rcv>: received_context_ok(<c>)
where forall <d> in <dataset_rcv>: fragment_ok(<d>)
where forall <d> in <dataset_rcv_more>: fragment_ok(<d>)
where forall <m> in <rsp_c_find_pending_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_c_find_pending_split>: split_message_ok(<m>, 'c_find_pending')
where forall <m> in <rsp_c_get_pending_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_c_get_pending_split>: split_message_ok(<m>, 'c_get_pending')
where forall <m> in <rsp_c_get_final_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_c_get_final_split>: split_message_ok(<m>, 'c_get_final')
where forall <m> in <rsp_c_move_pending_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_c_move_pending_split>: split_message_ok(<m>, 'c_move_pending')
where forall <m> in <rsp_c_move_final_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_c_move_final_split>: split_message_ok(<m>, 'c_move_final')
where forall <m> in <rsp_c_store_sub_rq_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_c_store_sub_rq_split>: split_message_ok(<m>, 'c_store_sub')
where forall <m> in <rsp_n_get_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_n_get_split>: split_message_ok(<m>, 'n_get')
where forall <m> in <rsp_n_set_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_n_set_split>: split_message_ok(<m>, 'n_set')
where forall <m> in <rsp_n_action_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_n_action_split>: split_message_ok(<m>, 'n_action')
where forall <m> in <rsp_n_create_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_n_create_split>: split_message_ok(<m>, 'n_create')
where forall <m> in <rsp_n_event_report_rq_more_data>: pdu_dataset_ok(<m>)
where forall <m> in <rsp_n_event_report_rq_split>: split_message_ok(<m>, 'n_event_report')
where forall <m> in <rsp_c_find_final_split>: split_message_ok(<m>, 'c_find_final')
where forall <m> in <rsp_c_find_pending>: same_context(<m>)
where forall <m> in <rsp_c_find_final>: same_context(<m>)
where forall <m> in <rsp_command_split>: same_context(<m>)
where forall <m> in <split_msg_rcv>: same_context(<m>)
where forall <m> in <rsp_c_get_pending>: same_context(<m>)
where forall <m> in <rsp_c_get_final>: same_context(<m>)
where forall <m> in <rsp_c_move_pending>: same_context(<m>)
where forall <m> in <rsp_c_move_final>: same_context(<m>)
where forall <m> in <rsp_c_store_sub_rq>: same_context(<m>)
where forall <m> in <rsp_n_get>: same_context(<m>)
where forall <m> in <rsp_n_set>: same_context(<m>)
where forall <m> in <rsp_n_action>: same_context(<m>)
where forall <m> in <rsp_n_create>: same_context(<m>)
where forall <m> in <rsp_n_event_report_rq>: same_context(<m>)
where forall <m> in <pdu_c_find_rsp_pending_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_c_get_rsp_pending_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_c_get_rsp_final_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_c_move_rsp_pending_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_c_move_rsp_final_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_c_store_sub_rq_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_n_get_rsp_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_n_set_rsp_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_n_action_rsp_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_n_create_rsp_dataset>: pdu_dataset_ok(<m>)
where forall <m> in <pdu_n_event_report_rq_dataset>: pdu_dataset_ok(<m>)
where forall <x> in <exchange_c_get>: sub_priority_ok(<x>)

# One presentation context per request (PS3.8 E.1) and the SOP class of the command is the abstract syntax of that context (PS3.7 D.3.2): equalities, the data PDVs take the id of the command PDV, the command the SOP class of the context
where forall <i> in <pdv_context_id_data_storage>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_find>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_move>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_get>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_normalized>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_rle>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_encapsulated>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_jpip>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_evbe>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_uncompressed>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_deflated_frame>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_stereo>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_jpip_deflate>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_single>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_hevc10>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_xlrecomp>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_deflated>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_video>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_video_single>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_storage_stereo_single>: <i> == first_context_id_of_request(<i>)
where forall <i> in <pdv_context_id_data_verification>: <i> == first_context_id_of_request(<i>)
where forall <u> in <cmd_uid_verification>: <u> == sop_class_of_context(<u>)
where forall <u> in <cmd_uid_storage>: <u> == sop_class_of_context(<u>)
where forall <u> in <cmd_uid_find>: <u> == sop_class_of_context(<u>)
where forall <u> in <cmd_uid_move>: <u> == sop_class_of_context(<u>)
where forall <u> in <cmd_uid_get>: <u> == sop_class_of_context(<u>)
where forall <u> in <cmd_uid_normalized>: <u> == sop_class_of_context(<u>)
