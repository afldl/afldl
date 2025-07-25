import enum

class TypeEnum(enum.IntEnum):
    @classmethod
    def _missing_(cls, value):
        obj = int.__new__(cls, value)
        obj._name_ = f'{cls.__name__}_{value}'
        obj._value_ = value
        return obj

class MsgFlag(enum.IntFlag):
    NONE = 0x00
    Encryption = 0x01
    Commit = 0x02
    Authentication = 0x04
    Initiator = 0x08
    CanUseHigherVersion = 0x10
    Response = 0x20

class Exchange(TypeEnum):
    IKE_BASE_1 = 1
    IDENTITY_1 = 2
    IKE_AUTH_1 = 3
    IKE_AGGRESIVE_1 = 4
    INFORMATIONAL_1 = 5
    TRANSACTION_1 = 6
    QUICK_1 = 32
    NEW_GROUP_1 = 33
    IKE_SA_INIT = 34
    IKE_AUTH = 35
    CREATE_CHILD_SA = 36
    INFORMATIONAL = 37
    IKE_SESSION_RESUME = 38
    GSA_AUTH = 39
    GSA_REGISTRATION = 40
    GSA_REKEY = 41

exchangeMap = {
    'SAINIT': Exchange.IKE_SA_INIT,    
    'AUTH': Exchange.IKE_AUTH,
    'CHILDSA': Exchange.CREATE_CHILD_SA,
    'INFO': Exchange.INFORMATIONAL
}

class Version(TypeEnum):
    IKEv1 = 0x10
    IKEv2 = 0x20
    
class CertCode(TypeEnum):
    PKCS7wrapped = 1 
    PGP = 2 
    DNSSignedKey = 3 
    X509CertificateSignature = 4
    KerberosToken = 6 
    CRL = 7
    ARL = 8 
    SPKI = 9 
    X509CertificateAttribute = 10 
    Deprecated = 11
    HashandURLofX509certificate = 12
    HashandURLofX509bundle = 13
    
class Payload(TypeEnum):
    NONE = 0
    SA_1 = 1
    PROPOSAL_1 = 2
    TRANSFORM_1 = 3
    KE_1 = 4
    ID_1 = 5
    CERT_1 = 6
    CERTREQ_1 = 7
    HASH_1 = 8
    SIG_1 = 9
    NONCE_1 = 10
    NOTIFY_1 = 11
    DELETE_1 = 12
    VENDOR_1 = 13
    CP_1 = 14
    SAK_1 = 15
    SAT_1 = 16
    KD_1 = 17
    SEQ_1 = 18
    POP_1 = 19
    NATD_1 = 20
    NATO_1 = 21
    GAP_1 = 22
    SA = 33
    KE = 34
    IDi = 35
    IDr = 36
    CERT = 37
    CERTREQ = 38
    AUTH = 39
    NONCE = 40
    NOTIFY = 41
    DELETE = 42
    VENDOR = 43
    TSi = 44
    TSr = 45
    SK = 46
    CP = 47
    EAP = 48
    GSPM = 49
    IDg = 50
    GSA = 51
    KD = 52
    SKF = 53
    PS = 54

class Protocol(TypeEnum):
    NONE = 0
    IKE = 1
    AH = 2
    ESP = 3
    FC_ESP_HEADER = 4
    FC_CT_AUTHENTICATION = 5

class Transform(TypeEnum):
    ENCR = 1
    PRF = 2
    INTEG = 3
    DH = 4
    ESN = 5

class EncrId(TypeEnum):
    ENCR_DES = 2
    ENCR_3DES = 3
    ENCR_RC5 = 4
    ENCR_IDEA = 5
    ENCR_CAST = 6
    ENCR_BLOWFISH = 7
    ENCR_3IDEA = 8
    ENCR_DES_IV32 = 9
    ENCR_NULL = 11
    ENCR_AES_CBC = 12
    ENCR_AES_CTR = 13
    ENCR_AES_CCM_8 = 14
    ENCR_AES_CCM_12 = 15
    ENCR_AES_CCM_16 = 16
    ENCR_AES_GCM_8 = 18
    ENCR_AES_GCM_12 = 19
    ENCR_AES_GCM_16 = 20
    ENCR_NULL_AUTH_AES_GMAC = 21
    ENCR_CAMELLIA_CBC = 23
    ENCR_CAMELLIA_CTR = 24
    ENCR_CAMELLIA_CCM_8 = 25
    ENCR_CAMELLIA_CCM_12 = 26
    ENCR_CAMELLIA_CCM_16 = 27
    ENCR_CHACHA20_POLY1305 = 28
    ENCR_AES_CCM_8_IIV = 29
    ENCR_AES_GCM_16_IIV = 30
    ENCR_CHACHA20_POLY1305_IIV = 31

class PrfId(TypeEnum):
    PRF_HMAC_MD5 = 1
    PRF_HMAC_SHA1 = 2
    PRF_HMAC_TIGER = 3
    PRF_AES128_XCBC = 4
    PRF_HMAC_SHA2_256 = 5
    PRF_HMAC_SHA2_384 = 6
    PRF_HMAC_SHA2_512 = 7
    PRF_AES128_CMAC = 8

class IntegId(TypeEnum):
    AUTH_NONE = 0
    AUTH_HMAC_MD5_96 = 1
    AUTH_HMAC_SHA1_96 = 2
    AUTH_DES_MAC = 3
    AUTH_KPDK_MD5 = 4
    AUTH_AES_XCBC_96 = 5
    AUTH_HMAC_MD5_128 = 6
    AUTH_HMAC_SHA1_160 = 7
    AUTH_AES_CMAC_96 = 8
    AUTH_AES_128_GMAC = 9
    AUTH_AES_192_GMAC = 10
    AUTH_AES_256_GMAC = 11
    AUTH_HMAC_SHA2_256_128 = 12
    AUTH_HMAC_SHA2_384_192 = 13
    AUTH_HMAC_SHA2_512_256 = 14

class DhId(TypeEnum):
    DH_NONE = 0
    DH_1 = 1
    DH_2 = 2
    DH_5 = 5
    DH_14 = 14
    DH_15 = 15
    DH_16 = 16
    DH_17 = 17
    DH_18 = 18
    DH_19 = 19
    DH_20 = 20
    DH_21 = 21
    DH_22 = 22
    DH_23 = 23
    DH_24 = 24
    DH_25 = 25
    DH_26 = 26
    DH_27 = 27
    DH_28 = 28
    DH_29 = 29
    DH_30 = 30
    DH_31 = 31
    DH_32 = 32

class EsnId(TypeEnum):
    NO_ESN = 0
    ESN = 1

TransformTable = {
    Transform.ENCR: EncrId,
    Transform.PRF: PrfId,
    Transform.INTEG: IntegId,
    Transform.DH: DhId,
    Transform.ESN: EsnId
}

class Notify(TypeEnum):
    UNSUPPORTED_CRITICAL_PAYLOAD = 1
    DOI_NOT_SUPPORTED = 2
    SITUATION_NOT_SUPPORTED = 3
    INVALID_IKE_SPI = 4
    INVALID_MAJOR_VERSION = 5
    INVALID_MINOR_VERSION = 6
    INVALID_SYNTAX = 7
    INVALID_FLAGS = 8
    INVALID_MESSAGE_ID = 9
    INVALID_PROTOCOL_ID = 10
    INVALID_SPI = 11
    INVALID_TRANSFORM_ID = 12
    ATTRIBUTES_NOT_SUPPORTED = 13
    NO_PROPOSAL_CHOSEN = 14
    BAD_PROPOSAL_SYNTAX = 15
    PAYLOAD_MALFORMED = 16
    INVALID_KE_PAYLOAD = 17
    INVALID_ID_INFORMATION = 18
    INVALID_CERT_ENCODING = 19
    INVALID_CERTIFICATE = 20
    CERT_TYPE_UNSUPPORTED = 21
    INVALID_CERT_AUTHORITY = 22
    INVALID_HASH_INFORMATION = 23
    AUTHENTICATION_FAILED = 24
    INVALID_SIGNATURE = 25
    ADDRESS_NOTIFICATION = 26
    NOTIFY_SA_LIFETIME = 27
    CERTIFICATE_UNAVAILABLE = 28
    UNSUPPORTED_EXCHANGE_TYPE = 29
    UNEQUAL_PAYLOAD_LENGTHS = 30
    SINGLE_PAIR_REQUIRED = 34
    NO_ADDITIONAL_SAS = 35
    INTERNAL_ADDRESS_FAILURE = 36
    FAILED_CP_REQUIRED = 37
    TS_UNACCEPTABLE = 38
    INVALID_SELECTORS = 39
    UNACCEPTABLE_ADDRESSES = 40
    UNEXPECTED_NAT_DETECTED = 41
    USE_ASSIGNED_HoA = 42
    TEMPORARY_FAILURE = 43
    CHILD_SA_NOT_FOUND = 44
    INVALID_GROUP_ID = 45
    AUTHORIZATION_FAILED = 46
    INITIAL_CONTACT = 16384
    SET_WINDOW_SIZE = 16385
    ADDITIONAL_TS_POSSIBLE = 16386
    IPCOMP_SUPPORTED = 16387
    NAT_DETECTION_SOURCE_IP = 16388
    NAT_DETECTION_DESTINATION_IP = 16389
    COOKIE = 16390
    USE_TRANSPORT_MODE = 16391
    HTTP_CERT_LOOKUP_SUPPORTED = 16392
    REKEY_SA = 16393
    ESP_TFC_PADDING_NOT_SUPPORTED = 16394
    NON_FIRST_FRAGMENTS_ALSO = 16395
    MOBIKE_SUPPORTED = 16396
    ADDITIONAL_IP4_ADDRESS = 16397
    ADDITIONAL_IP6_ADDRESS = 16398
    NO_ADDITIONAL_ADDRESSES = 16399
    UPDATE_SA_ADDRESSES = 16400
    COOKIE2 = 16401
    NO_NATS_ALLOWED = 16402
    AUTH_LIFETIME = 16403
    MULTIPLE_AUTH_SUPPORTED = 16404
    ANOTHER_AUTH_FOLLOWS = 16405
    REDIRECT_SUPPORTED = 16406
    REDIRECT = 16407
    REDIRECTED_FROM = 16408
    TICKET_LT_OPAQUE = 16409
    TICKET_REQUEST = 16410
    TICKET_ACK = 16411
    TICKET_NACK = 16412
    TICKET_OPAQUE = 16413
    LINK_ID = 16414
    USE_WESP_MODE = 16415
    ROHC_SUPPORTED = 16416
    EAP_ONLY_AUTHENTICATION = 16417
    CHILDLESS_IKEV2_SUPPORTED = 16418
    QUICK_CRASH_DETECTION = 16419
    IKEV2_MESSAGE_ID_SYNC_SUPPORTED = 16420
    IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED = 16421
    IKEV2_MESSAGE_ID_SYNC = 16422
    IPSEC_REPLAY_COUNTER_SYNC = 16423
    SECURE_PASSWORD_METHODS = 16424
    PSK_PERSIST = 16425
    PSK_CONFIRM = 16426
    ERX_SUPPORTED = 16427
    IFOM_CAPABILITY = 16428
    SENDER_REQUEST_ID = 16429
    IKEV2_FRAGMENTATION_SUPPORTED = 16430
    SIGNATURE_HASH_ALGORITHMS = 16431
    CLONE_IKE_SA_SUPPORTED = 16432
    CLONE_IKE_SA = 16433
    PUZZLE = 16434
    USE_PPK = 16435
    PPK_IDENTITY = 16436
    NO_PPK_AUTH = 16437
    RESPONDER_LIFETIME = 24576
    REPLAY_STATUS = 24577
    INITIAL_CONTACT_1 = 24578
    ISAKMP_NTYPE_R_U_THERE = 36136
    ISAKMP_NTYPE_R_U_THERE_ACK = 36137
    ISAKMP_NTYPE_LOAD_BALANCE = 40501
    ISAKMP_NTYPE_HEARTBEAT = 40503

class IDType(TypeEnum):
    ID_ANY = 0
    ID_IPV4_ADDR = 1
    ID_FQDN = 2
    ID_RFC822_ADDR = 3
    ID_IPV4_ADDR_SUBNET = 4
    ID_IPV6_ADDR = 5
    ID_IPV6_ADDR_SUBNET = 6
    ID_IPV4_ADDR_RANGE = 7
    ID_IPV6_ADDR_RANGE = 8
    ID_DER_ASN1_DN = 9
    ID_DER_ASN1_GN = 10
    ID_KEY_ID = 11
    ID_FC_NAME = 12
    ID_NULL = 13

class AuthMethod(TypeEnum):
    RSA = 1
    PSK = 2
    DSS = 3
    ECDSA_SHA_256 = 9
    ECDSA_SHA_384 = 10
    ECDSA_SHA_512 = 11
    GENERIC = 12
    NULL_AUTH = 13
    DIGITAL = 14

class CFGType(TypeEnum):
    CFG_REQUEST = 1
    CFG_REPLY = 2
    CFG_SET = 3
    CFG_ACK = 4

class CPAttrType(TypeEnum):
    INTERNAL_IP4_ADDRESS = 1
    INTERNAL_IP4_NETMASK = 2
    INTERNAL_IP4_DNS = 3
    INTERNAL_IP4_NBNS = 4
    INTERNAL_ADDRESS_EXPIRY = 5
    INTERNAL_IP4_DHCP = 6
    APPLICATION_VERSION = 7
    INTERNAL_IP6_ADDRESS = 8
    INTERNAL_IP6_DNS = 10
    INTERNAL_IP6_DHCP = 12
    INTERNAL_IP4_SUBNET = 13
    SUPPORTED_ATTRIBUTES = 14
    INTERNAL_IP6_SUBNET = 15
    MIP6_HOME_PREFIX = 16
    INTERNAL_IP6_LINK = 17
    INTERNAL_IP6_PREFIX = 18
    HOME_AGENT_ADDRESS = 19
    P_CSCF_IP4_ADDRESS = 20
    P_CSCF_IP6_ADDRESS = 21
    FTT_KAT = 22
    EXTERNAL_SOURCE_IP4_NAT_INFO = 23
    TIMEOUT_PERIOD_FOR_LIVENESS_CHECK = 24
    INTERNAL_DNS_DOMAIN = 25
    INTERNAL_DNSSEC_TA = 26
    XAUTH_TYPE = 16520
    XAUTH_USER_NAME = 16521
    XAUTH_USER_PASSWORD = 16522
    XAUTH_PASSCODE = 16523
    XAUTH_MESSAGE = 16524
    XAUTH_CHALLENGE = 16525
    XAUTH_DOMAIN = 16526
    XAUTH_STATUS = 16527
    UNITY_BANNER = 28672
    UNITY_SAVE_PASSWD = 28673
    UNITY_DEF_DOMAIN = 28674
    UNITY_SPLITDNS_NAME = 28675
    UNITY_SPLIT_INCLUDE = 28676
    UNITY_NATT_PORT = 28677
    UNITY_LOCAL_LAN = 28678
    UNITY_PFS = 28679
    UNITY_FW_TYPE = 28680
    UNITY_BACKUP_SERVERS = 28681
    UNITY_DDNS_HOSTNAME = 28682
    CICSO_UNKNOWN_SEEN_ON_IPHONE = 28683

class TSType(TypeEnum):
    TS_IPV4_ADDR_RANGE = 7
    TS_IPV6_ADDR_RANGE = 8
    TS_FC_ADDR_RANGE = 9

class IpProto(TypeEnum):
    ANY = 0
    ICMP = 1
    IGMP = 2
    GGP = 3
    IPV4 = 4
    TCP = 6
    UDP = 17
    RDP = 27
    IPV6 = 41
    ESP = 50
    ICMPV6 = 58
    MH = 135
    RAW = 255

class EAPCode(TypeEnum):
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    INITIATE = 5
    FINISH = 6

class TransformAttr(TypeEnum):
    ENCR = 1
    HASH = 2
    AUTH = 3
    DH = 4
    DH_TYPE = 5
    DH_PRIME = 6
    GENERATOR_1 = 7
    GENERATOR_2 = 8
    CURVE_A = 9
    CURVE_B = 10
    LIFETYPE = 11
    DURATION = 12
    PRF = 13
    KEY_LENGTH = 14
    FIELD_SIZE = 15
    DH_ORDER = 16

class ESPAttr(TypeEnum):
    LIFE_TYPE = 1
    DURATION = 2
    GRP_DESC = 3
    ENC_MODE = 4
    AUTH = 5
    KEY_LENGTH = 6
    KEY_ROUND = 7
    COMP_DICT_SIZE = 8
    COMP_PRIVALG = 9
    SECCTX = 10
    ESN = 11
    AUTH_KEY_LENGTH = 12
    SIG_ALGORITHM = 13
    ADDR_PRESERVE = 14
    SA_DIRECTION = 15


class EncModeId_1(TypeEnum):
    ANY = 0
    TUNNEL = 1
    TRNS = 2
    UDPTUNNEL_RFC = 3
    UDPTRNS_RFC = 4
    UDPTUNNEL_DRAFT = 61443
    UDPTRNS_DRAFT = 61444


class EncModeId_1_for_scan(TypeEnum):
    ANY = 0
    TUNNEL = 1
    TRNS = 2


class IntegId_1_AH(TypeEnum):
    AUTH_NONE = 0
    AUTH_HMAC_MD5 = 2
    AUTH_HMAC_SHA1 = 3
    AUTH_DES_MAC = 4


class IntegId_1(TypeEnum):
    AUTH_NONE = 0
    AUTH_HMAC_MD5 = 1
    AUTH_HMAC_SHA1 = 2
    AUTH_DES_MAC = 3
    AUTH_KPDK = 4
    AUTH_HMAC_SHA2_256 = 5
    AUTH_HMAC_SHA2_384 = 6
    AUTH_HMAC_SHA2_512 = 7
    AUTH_HMAC_RIPEMD = 8
    AUTH_AES_XCBC_MAC = 9
    AUTH_SIG_RSA = 10
    AUTH_AES_128_GMAC = 11
    AUTH_AES_192_GMAC = 12
    AUTH_AES_256_GMAC = 13

class IntegId_1_for_scan(TypeEnum):
    AUTH_NONE = 0
    AUTH_HMAC_MD5 = 1
    AUTH_HMAC_SHA1 = 2
    AUTH_DES_MAC = 3
    AUTH_HMAC_SHA2_256 = 5
    AUTH_HMAC_SHA2_384 = 6
    AUTH_HMAC_SHA2_512 = 7
    AUTH_AES_XCBC_MAC = 9
    AUTH_SIG_RSA = 10

ESPTable_1 = {
    ESPAttr.ENC_MODE: EncModeId_1,
    ESPAttr.AUTH: IntegId_1,
}

class EncrId_1(TypeEnum):
    DES_CBC = 1
    IDEA_CBC = 2
    BLOWFISH_CBC = 3
    RC5_R16_B64_CBC = 4
    _3DES_CBC = 5
    CAST_CBC = 6
    AES_CBC = 7
    CAMELLIA_CBC = 8

class HashId_1(TypeEnum):
    MD5 = 1
    SHA1 = 2
    TIGER = 3
    SHA2_256 = 4
    SHA2_384 = 5
    SHA2_512 = 6

class AuthId_1(TypeEnum):
    PSK = 1
    DSS = 2
    RSA = 3
    ENCR_RSA = 4
    RE_ENCR_RSA = 5
    ECDSA_SHA_256 = 9
    ECDSA_SHA_384 = 10
    ECDSA_SHA_512 = 11
    XAUTHInitPreShared = 65001
    XAUTHRespPreShared = 65002
    XAUTHInitDSS       = 65003
    XAUTHRespDSS       = 65004
    XAUTHInitRSA       = 65005
    XAUTHRespRSA       = 65006
    XAUTHInitRSAEncryption = 65007
    XAUTHRespRSAEncryption = 65008
    XAUTHInitRSARevisedEncryption = 65009
    XAUTHRespRSARevisedEncryption = 65010

TransformTable_1 = {
    TransformAttr.ENCR: EncrId_1,
    TransformAttr.HASH: HashId_1,
    TransformAttr.AUTH: AuthId_1,
    TransformAttr.DH: DhId,
}

class L2TPType(TypeEnum):
    SCCRQ = 1
    SCCRP = 2
    SCCCN = 3
    StopCCN = 4
    HELLO = 6
    OCRQ = 7
    OCRP = 8
    OCCN = 9
    ICRQ = 10
    ICRP = 11
    ICCN = 12
    CDN = 14
    WEN = 15
    SLI = 16

class L2TPAttr(TypeEnum):
    MsgType = 0
    RandomVector = 36
    Result = 1
    Version = 2
    FramingCap = 3
    BearerCap = 4
    TieBreaker = 5
    Firmware = 6
    HostName = 7
    VendorName = 8
    TunnelID = 9
    WindowSize = 10
    Challenge = 11
    Response = 13
    CauseCode = 12
    SessionID = 14
    CallSerial = 15
    MinimumBPS = 16
    MaximumBPS = 17
    BearerType = 18
    FramingType = 19
    CalledNumber = 21
    CallingNumber = 22
    SubAddress = 23
    ConnectSpeed = 24
    RxConnectSpeed = 38
    PhysicalChannel = 25
    PrivateGroupID = 37
    SequencingRequired = 39
    InitialLCP = 26
    LastSentLCP = 27
    LastReceivedLCP = 28
    ProxyAuthenType = 29
    ProxyAuthenName = 30
    ProxyAuthenChallenge = 31
    ProxyAuthenID = 32
    ProxyAuthenResponse = 33
    CallErrors = 34
    ACCM = 35

class Response(TypeEnum):
    # NONE = -1
    No_response = 71
    Error = 72
    DecryptedError = 73
    Other = 74
    No_child_SA = 75
    No_IKE_SA = 76
    Have_Rekeyed = 77
    Un_supported = 78
    main_mode_1 = 51
    multi_sa_main_mode_1 = 41
    main_mode_2 = 52
    main_mode_3 = 53
    plain_main_mode_3 = 43
    quick_mode_1 = 54
    delete_ESP = 55
    delete_IKE = 56
    aggressive_mode_1 = 57

    main_mode_2_half = 74

    quick_mode_2 = 58
    ESP_reply = 59
    wrong_ESP_reply = 99
    ESP_more = 60

    IKE_SA_INIT = 61
    IKE_AUTH = 62
    REKEY_IKE = 63
    REKEY_IPsec = 64
    IKE_delete_ESP = 65
    IKE_delete_IKE = 66

    OK = 51
    PortUnreachable = 101

class KeyLength(TypeEnum):
    AES_128 = 128
    AES_192 = 192
    AES_256 = 256


class KeyLength_ESP(TypeEnum):
    _128 = 128
    _192 = 192
    _256 = 256


class EncrId_for_scan(TypeEnum):
    ENCR_DES = 2
    ENCR_3DES = 3
    ENCR_RC5 = 4
    ENCR_NULL = 11
    ENCR_AES_CBC = 12
    ENCR_AES_CTR = 13
    ENCR_AES_CCM_8 = 14
    ENCR_AES_GCM_8 = 18
    ENCR_NULL_AUTH_AES_GMAC = 21

class message_name(TypeEnum):
    fuzz_mode = 0
    main_mode_1 = 1
    main_mode_2 = 2
    main_mode_3 = 3
    quick_mode_1 = 4
    quick_mode_2 = 5
    new_group = 6
    test_trans_ESP = 7
    delete_ESP = 8
    delete_IKE = 9

    IKE_SA_INIT = 11
    IKE_AUTH = 12
    REKEY_IKE = 13
    IKE_delete_ESP = 14
    IKE_delete_IKE = 15

    aggressive_mode_1 = 21
    aggressive_mode_2 = 22
    
class DOI(TypeEnum):
    IPsec = 1
    AH = 2
    ESP = 3

crypt_algo_map = {
    EncrId.ENCR_NULL: 'NULL',
    EncrId.ENCR_AES_CBC: 'AES-CBC',
    EncrId.ENCR_DES: 'DES',
    EncrId.ENCR_3DES: '3DES',
}

auth_algo_map = {
    IntegId_1.AUTH_NONE: "NULL",
    IntegId_1.AUTH_HMAC_MD5: "HMAC-MD5-96",
    IntegId_1.AUTH_HMAC_SHA1: "HMAC-SHA1-96",
    IntegId_1.AUTH_HMAC_SHA2_256: "SHA2-256-128",
    IntegId_1.AUTH_HMAC_SHA2_384: "SHA2-384-192",
    IntegId_1.AUTH_HMAC_SHA2_512: "SHA2-512-256",
}