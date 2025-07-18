import struct, io, collections, os, random, ipaddress
from pesp4 import enums

IKEv2attrs = {
                enums.Transform.ENCR: (enums.EncrId.ENCR_AES_CBC, enums.KeyLength.AES_128),
                enums.Transform.PRF: (enums.PrfId.PRF_HMAC_SHA1, None),
                enums.Transform.INTEG: (enums.IntegId.AUTH_HMAC_SHA1_96, None),
                enums.Transform.DH: (enums.DhId.DH_5, None),
                enums.Transform.ESN: (None, None)
            }

IKEv2ESPattrs = {
                enums.Transform.ENCR: (enums.EncrId.ENCR_AES_CBC, enums.KeyLength.AES_128),
                enums.Transform.PRF: (None, None),
                enums.Transform.INTEG: (enums.IntegId.AUTH_HMAC_SHA1_96, None),
                enums.Transform.DH: (None, None),
                enums.Transform.ESN: (enums.EsnId.NO_ESN, None)
            }

# cisco: aes 128 sha1 1024
IKE_attr_values = collections.OrderedDict()
# IKE_attr_values[enums.TransformAttr.ENCR] = enums.EncrId_1._3DES_CBC
# IKE_attr_values[enums.TransformAttr.DH] = enums.DhId.DH_2
IKE_attr_values[enums.TransformAttr.ENCR] = enums.EncrId_1.AES_CBC
IKE_attr_values[enums.TransformAttr.KEY_LENGTH] = 128
IKE_attr_values[enums.TransformAttr.HASH] = enums.HashId_1.SHA1
IKE_attr_values[enums.TransformAttr.DH] = enums.DhId.DH_2

ESP_attr_values = collections.OrderedDict()
ESP_attr_values[enums.ESPAttr.KEY_LENGTH] = 128
ESP_attr_values[enums.ESPAttr.AUTH] = enums.IntegId_1.AUTH_HMAC_SHA1
ESP_T_id = enums.EncrId.ENCR_AES_CBC
# ESP_T_id = enums.EncrId.ENCR_3DES

AH_attr_values = collections.OrderedDict()
AH_attr_values[enums.ESPAttr.ENC_MODE] = enums.EncModeId_1.TRNS
AH_attr_values[enums.ESPAttr.AUTH] = enums.IntegId_1.AUTH_HMAC_SHA1
AH_T_id = enums.IntegId_1_AH.AUTH_HMAC_SHA1

L2TP_data = b"\xc8\x02\x00\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x80\x08\x00\x00\x00\x00\x00\x01\x80\x08\x00\x00\x00\x02\x01\x00\x80\x0a\x00\x00\x00\x03\x00\x00\x00\x01\x80\x0a\x00\x00\x00\x04\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x0a\x00\x80\x15\x00\x00\x00\x07\x44\x45\x53\x4b\x54\x4f\x50\x2d\x43\x4b\x56\x42\x38\x54\x4d\x00\x0f\x00\x00\x00\x08\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x80\x08\x00\x00\x00\x09\x00\x0f\x80\x08\x00\x00\x00\x0a\x00\x08"

func_dir = {
    "main_mode_1": "send_main_mode_1",
    "main_mode_2": "send_main_mode_2",
    "main_mode_3": "send_main_mode_3",
    "quick_mode_1": "send_quick_mode_1",
    "quick_mode_1_with_group": "send_quick_mode_1_with_group",
    "quick_mode_2": "send_quick_mode_2",
    "aggressive_mode_1": "send_aggressive_mode_1",
    "aggressive_mode_2": "send_aggressive_mode_2",
    "new_group": "send_new_group",
    "test_trans_ESP": "test_trans_ESP",
    "test_tunnel_ESP": "test_tunnel_ESP",
    "delete_ESP": "send_delete_ESP",
    "delete_IKE": "send_delete_IKE",
    "wrong_nonce_main_mode_2" : "send_wrong_nonce_main_mode_2",
    "multi_sa_main_mode_1" : "send_multi_sa_main_mode_1",
    "wrong_order_quick_mode_1" : "send_wrong_order_quick_mode_1"
}

crypt_algo_map = {
    enums.EncrId.ENCR_NULL: 'NULL',
    enums.EncrId.ENCR_AES_CBC: 'AES-CBC',
    enums.EncrId.ENCR_DES: 'DES',
    enums.EncrId.ENCR_3DES: '3DES',
}

auth_algo_map = {
    enums.IntegId_1.AUTH_NONE: "NULL",
    enums.IntegId_1.AUTH_HMAC_MD5: "HMAC-MD5-96",
    enums.IntegId_1.AUTH_HMAC_SHA1: "HMAC-SHA1-96",
    enums.IntegId_1.AUTH_HMAC_SHA2_256: "SHA2-256-128",
    enums.IntegId_1.AUTH_HMAC_SHA2_384: "SHA2-384-192",
    enums.IntegId_1.AUTH_HMAC_SHA2_512: "SHA2-512-256",
}

DH_group = {
    0: "DH_None",
    1: "DH_768_bit_MODP",
    2: "DH_1024_bit_MODP",
    5: "DH_1536_bit_MODP",
    14: "DH_2048_bit_MODP",
    15: "DH_3072_bit_MODP",
    16: "DH_4096_bit_MODP",
    17: "DH_6144_bit_MODP",
    18: "DH_8192_bit_MODP",
    19: "ECDH_256_bit_Random_ECP",
    20: "ECDH_384_bit_Random_ECP",
    21: "ECDH_521_bit_Random_ECP",
    22: "1024_bit_MODP_with_160_bit_Prime_Order_Subgroup",
    23: "2048_bit_MODP_with_224_bit_Prime_Order_Subgroup",
    24: "2048_bit_MODP_with_256_bit_Prime_Order_Subgroup",
    25: "ECDH_192_bit_Random_ECP",
    26: "ECDH_224_bit_Random_ECP",
    27: "ECDH_224_bit_Random_ECP",
    28: "ECDH_256_bit_Random_ECP",
    29: "ECDH_384_bit_Random_ECP",
    30: "ECDH_512_bit_Random_ECP",
    31: "",
    32: "",
}