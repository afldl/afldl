import random, hashlib,collections
from scapy.all import *
from pesp4 import enums
import logging
from multiprocessing import Process
import time
import random
import networkx as nx

IKE_ENCR_map = {
    "AES_CBC":enums.EncrId_1.AES_CBC,
    "_3DES_CBC":enums.EncrId_1._3DES_CBC,
    "DES_CBC":enums.EncrId_1.DES_CBC
}

IKE_HASH_map = {
    "MD5" : enums.HashId_1.MD5,
    "SHA1" :enums.HashId_1.SHA1,
    "TIGER" : enums.HashId_1.TIGER,
    "SHA2_256" : enums.HashId_1.SHA2_256,
    "SHA2_384" : enums.HashId_1.SHA2_384,
    "SHA2_512" : enums.HashId_1.SHA2_512
}    
IKE_DH_map = {
    "DH_NONE" : enums.DhId.DH_NONE,
    "DH_1" : enums.DhId.DH_1,
    "DH_2" : enums.DhId.DH_2,
    "DH_5" : enums.DhId.DH_5,
    "DH_14" : enums.DhId.DH_14,
    "DH_15" : enums.DhId.DH_15,
    "DH_16" : enums.DhId.DH_16,
    "DH_17" : enums.DhId.DH_17,
    "DH_18" : enums.DhId.DH_18,
    "DH_19" : enums.DhId.DH_19,
    "DH_20" : enums.DhId.DH_20,
    "DH_21" : enums.DhId.DH_21,
    "DH_22" : enums.DhId.DH_22,
    "DH_23" : enums.DhId.DH_23,
    "DH_24" : enums.DhId.DH_24,
    "DH_25" : enums.DhId.DH_25,
    "DH_26" : enums.DhId.DH_26,
    "DH_27" : enums.DhId.DH_27,
    "DH_28" : enums.DhId.DH_28,
    "DH_29" : enums.DhId.DH_29,
    "DH_30" : enums.DhId.DH_30,
    "DH_31" : enums.DhId.DH_31,
    "DH_32" : enums.DhId.DH_32
}
DhId_map = {
    "DH_NONE" : enums.DhId.DH_NONE,
    "DH_1" : enums.DhId.DH_1,
    "DH_2" : enums.DhId.DH_2,
    "DH_5" : enums.DhId.DH_5,
    "DH_14" : enums.DhId.DH_14,
    "DH_15" : enums.DhId.DH_15,
    "DH_16" : enums.DhId.DH_16,
    "DH_17" : enums.DhId.DH_17,
    "DH_18" : enums.DhId.DH_18,
    "DH_19" : enums.DhId.DH_19,
    "DH_20" : enums.DhId.DH_20,
    "DH_21" : enums.DhId.DH_21,
    "DH_22" : enums.DhId.DH_22,
    "DH_23" : enums.DhId.DH_23,
    "DH_24" : enums.DhId.DH_24,
    "DH_25" : enums.DhId.DH_25,
    "DH_26" : enums.DhId.DH_26,
    "DH_27" : enums.DhId.DH_27,
    "DH_28" : enums.DhId.DH_28,
    "DH_29" : enums.DhId.DH_29,
    "DH_30" : enums.DhId.DH_30,
    "DH_31" : enums.DhId.DH_31,
    "DH_32" : enums.DhId.DH_32
}

ESP_ENC_MODE_map = {
    "ANY" : enums.EncModeId_1.ANY,
    "TUNNEL" : enums.EncModeId_1.TUNNEL,
    "TRNS" : enums.EncModeId_1.TRNS,
    "UDPTUNNEL_RFC" : enums.EncModeId_1.UDPTUNNEL_RFC,
    "UDPTRNS_RFC" : enums.EncModeId_1.UDPTRNS_RFC,
    "UDPTUNNEL_DRAFT" : enums.EncModeId_1.UDPTUNNEL_DRAFT,
    "UDPTRNS_DRAFT" : enums.EncModeId_1.UDPTRNS_DRAFT
}

ESP_AUTH_map = {
    "AUTH_NONE":enums.IntegId_1.AUTH_NONE,
    "AUTH_HMAC_MD5":enums.IntegId_1.AUTH_HMAC_MD5,
    "AUTH_HMAC_SHA1":enums.IntegId_1.AUTH_HMAC_SHA1,
    "AUTH_HMAC_SHA2_256":enums.IntegId_1.AUTH_HMAC_SHA2_256,
    "AUTH_HMAC_SHA2_384":enums.IntegId_1.AUTH_HMAC_SHA2_384,
    "AUTH_HMAC_SHA2_512":enums.IntegId_1.AUTH_HMAC_SHA2_512,
}

ESP_T_id_map = {
    "ENCR_AES_GCM_16":enums.EncrId.ENCR_AES_GCM_16,
    "ENCR_AES_CBC":enums.EncrId.ENCR_AES_CBC,
    "ENCR_3DES":enums.EncrId.ENCR_3DES,
    "ENCR_DES":enums.EncrId.ENCR_DES
}


EncrId_map = {
    "ENCR_AES_GCM_16":enums.EncrId.ENCR_AES_GCM_16,
    "ENCR_AES_CBC":enums.EncrId.ENCR_AES_CBC,
    "ENCR_3DES":enums.EncrId.ENCR_3DES,
    "ENCR_DES":enums.EncrId.ENCR_DES
}

AH_T_id_map = {
        "AUTH_NONE" : enums.IntegId_1_AH.AUTH_NONE,
        "AUTH_HMAC_MD5" :enums.IntegId_1_AH.AUTH_HMAC_MD5,
        "AUTH_HMAC_SHA1" : enums.IntegId_1_AH.AUTH_HMAC_SHA1,
        "AUTH_DES_MAC" : enums.IntegId_1_AH.AUTH_DES_MAC
    
}

PRF_map = {
   "PRF_HMAC_SHA1": enums.PrfId.PRF_HMAC_SHA1,
   "PRF_HMAC_MD5": enums.PrfId.PRF_HMAC_MD5,
   "PRF_HMAC_TIGER": enums.PrfId.PRF_HMAC_TIGER,
   "PRF_AES128_XCBC": enums.PrfId.PRF_AES128_XCBC,
   "PRF_HMAC_SHA2_256": enums.PrfId.PRF_HMAC_SHA2_256,
   "PRF_HMAC_SHA2_384": enums.PrfId.PRF_HMAC_SHA2_384,
   "PRF_HMAC_SHA2_512": enums.PrfId.PRF_HMAC_SHA2_512,
   "PRF_AES128_CMAC": enums.PrfId.PRF_AES128_CMAC,
}



IntegId_map = {
   "AUTH_NONE": enums.IntegId.AUTH_NONE,
   "AUTH_HMAC_MD5_96": enums.IntegId.AUTH_HMAC_MD5_96,
   "AUTH_HMAC_SHA1_96": enums.IntegId.AUTH_HMAC_SHA1_96,
   "AUTH_DES_MAC": enums.IntegId.AUTH_DES_MAC,
   "AUTH_KPDK_MD5": enums.IntegId.AUTH_KPDK_MD5,
   "AUTH_AES_XCBC_96": enums.IntegId.AUTH_AES_XCBC_96,
   "AUTH_HMAC_MD5_128": enums.IntegId.AUTH_HMAC_MD5_128,
   "AUTH_HMAC_SHA1_160": enums.IntegId.AUTH_HMAC_SHA1_160,
   "AUTH_AES_CMAC_96": enums.IntegId.AUTH_AES_CMAC_96,
   "AUTH_AES_128_GMAC": enums.IntegId.AUTH_AES_128_GMAC,
   "AUTH_AES_192_GMAC": enums.IntegId.AUTH_AES_192_GMAC,
   "AUTH_AES_256_GMAC": enums.IntegId.AUTH_AES_256_GMAC,
   "AUTH_HMAC_SHA2_256_128": enums.IntegId.AUTH_HMAC_SHA2_256_128,
   "AUTH_HMAC_SHA2_384_192": enums.IntegId.AUTH_HMAC_SHA2_384_192,
   "AUTH_HMAC_SHA2_512_256": enums.IntegId.AUTH_HMAC_SHA2_512_256,

}

EsnId_map = {
    "NO_ESN" : enums.EsnId.NO_ESN,
    "ESN" : enums.EsnId.ESN
}

KeyLength_map = {
    "AES_128" : enums.KeyLength.AES_128,
    "AES_192" : enums.KeyLength.AES_192,
    "AES_256" : enums.KeyLength.AES_256
}

def init_log(file_name):


    formatter = '%(asctime)s -- %(filename)s[line:%(lineno)d] %(levelname)s\t%(message)s'
    logging.basicConfig(filename=file_name, format=formatter, level=logging.DEBUG)


def str2list(lstr):
    lstr = lstr.strip('[]')
    lst = [out.strip("''") for out in lstr.split(', ')]
    return lst


def tuple_str2list(db_str):
    db_str = db_str.strip("()")
    db_str = [out.strip("''") for out in db_str.split(', ')]
    return db_str

def hash(string):
    hash_obj = hashlib.md5()
    hash_obj.update(string.encode('utf-8'))
    return hash_obj.hexdigest()

def get_most_respose(sul,querys,max_test):
    resposes = []
    for i in range(int(max_test)):
        resposes.append(str(sul.sul.query(querys)))
    return str2list(collections.Counter(resposes).most_common(1)[0][0])

def ip_mac_scanner_sim(hosts: str, local_mac: str):
    """
    网段IP&Mac ARP协议扫描器
    :param hosts: 网段 e.g.'*.*.*.*'
    :param local_mac: 本地MAC地址,e.g.'**:**:**:**:**:**,
    :return: dict { IP: MAC, .... }
    """
    from scapy.layers.l2 import Ether, ARP
    from scapy.sendrecv import srp
 
    packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac)/ARP(pdst=hosts)
    _Answer, _unAnswer = srp(packet, timeout=2, verbose=0)
    result = {}
    for Send, Receive in _Answer:
        result[Receive[ARP].psrc] = Receive[ARP].hwsrc
    return result

def reassemble_udp_packets(packets):
    reassembled_packets = []
    ids = []
    i = -1
    while i < len(packets)-1:
        i += 1
        if IP in packets[i] and UDP in packets[i] and packets[i][UDP].dport == 500:
            ip = packets[i][IP]
            if ip.id in ids: # skip repeated ip packet
                continue
            ids.append(ip.id)
            udp = packets[i][UDP]
            reassembled_packet = IP(src=ip.src, dst=ip.dst) / UDP(sport=udp.sport, dport=udp.dport)
            udp_payload = raw(udp.payload)
            offset = len(ip.payload)
            
            # 查找分片
            while ip.flags == 'MF':
                i += 1
                ip = packets[i][IP]
                if ip.frag * 8 == offset:
                    udp_payload += raw(ip.payload)
                    offset += len(ip.payload)
                
            reassembled_packet /= udp_payload
            reassembled_packets.append(reassembled_packet)
    
    # 查找分片时可能有漏掉的udp包
    for i in range(len(packets)):
        if IP in packets[i] and UDP in packets[i] and packets[i][UDP].dport == 500:
            ip = packets[i][IP]
            if ip.id in ids: # skip repeated ip packet
                continue
            ids.append(ip.id) 
            reassembled_packets.append(packets[i])
        
    return reassembled_packets

def ipsec_config_v1(ipsec_config):
    
    IKE_attr_values_dict = ipsec_config['IKE_attr_values']
    ESP_attr_values_dict = ipsec_config['ESP_attr_values']
    AH_attr_values_dict = ipsec_config['AH_attr_values']
    
    ESP_T_id_str = ipsec_config['ESP_T_id']
    AH_T_id_str = ipsec_config['AH_T_id']
    


    # cisco: aes 128 sha1 1024
    IKE_attr_values = collections.OrderedDict()
    IKE_attr_values[enums.TransformAttr.ENCR] = IKE_ENCR_map[IKE_attr_values_dict['ENCR']]
    if "KEY_LENGTH" in IKE_attr_values_dict:
        IKE_attr_values[enums.TransformAttr.KEY_LENGTH] = int(IKE_attr_values_dict['KEY_LENGTH'])
    IKE_attr_values[enums.TransformAttr.HASH] = IKE_HASH_map[IKE_attr_values_dict['HASH']]
    IKE_attr_values[enums.TransformAttr.DH] = IKE_DH_map[IKE_attr_values_dict['DH']]

    ESP_attr_values = collections.OrderedDict()
    if "KEY_LENGTH" in ESP_attr_values_dict:
        ESP_attr_values[enums.ESPAttr.KEY_LENGTH] = int(ESP_attr_values_dict['KEY_LENGTH'])
    ESP_attr_values[enums.ESPAttr.AUTH] = ESP_AUTH_map[ESP_attr_values_dict['AUTH']]
    ESP_T_id = ESP_T_id_map[ESP_T_id_str]

    AH_attr_values = collections.OrderedDict()
    AH_attr_values[enums.ESPAttr.ENC_MODE] = ESP_ENC_MODE_map[AH_attr_values_dict['ENC_MODE']]
    AH_attr_values[enums.ESPAttr.AUTH] = ESP_AUTH_map[AH_attr_values_dict['AUTH']]
    AH_T_id = AH_T_id_map[AH_T_id_str]


    return IKE_attr_values,ESP_attr_values,ESP_T_id,AH_attr_values,AH_T_id


def v2_map_attr(_dict):
    attr = {}
    if "ENCR" in _dict and _dict["ENCR"] != "":
        if "KeyLength" in _dict and _dict["KeyLength"] != "":
            attr[enums.Transform.ENCR] = (EncrId_map[_dict["ENCR"]],KeyLength_map[_dict["KeyLength"]])
        else:
            attr[enums.Transform.ENCR] = (EncrId_map[_dict["ENCR"]],None)
    else:
        attr[enums.Transform.ENCR] = (None,None)
        
    if "PRF" in _dict and _dict["PRF"] != "":
        attr[enums.Transform.PRF] =  (PRF_map[_dict["PRF"]],None)
    else:
        attr[enums.Transform.PRF]  = (None,None)
    if "INTEG" in _dict and _dict["INTEG"] != "" :
        attr[enums.Transform.INTEG] = (IntegId_map[_dict["INTEG"]],None)
    else:
        attr[enums.Transform.INTEG] = (None,None)
        
    if "DH" in _dict and _dict["DH"] != "" :
        attr[enums.Transform.DH] = (DhId_map[_dict["DH"]],None)
    else:
        attr[enums.Transform.DH] = (None,None)
    if "ESN" in _dict and _dict["ESN"] != "" :
        attr[enums.Transform.ESN] = (EsnId_map[_dict["ESN"]],None)
    else:
        attr[enums.Transform.ESN] = (None,None)

    return attr

def ipsec_config_v2(ipsec_config):
    IKE_attrs = v2_map_attr(ipsec_config['IKE'])
    ESP_attrs = v2_map_attr(ipsec_config['ESP'])
    AH_attrs = v2_map_attr(ipsec_config['AH']) if 'AH' in ipsec_config else None



    return IKE_attrs,ESP_attrs,AH_attrs

import re,sys,glob,os,pickle

def red_dot(dir1,version,happy_flow = None):



    # dir1 = sys.argv[1]
    # version = 'v1'

    # dir1 = 'cisco_2951_v1'

    # version = 'v1'
    if happy_flow == None:
        if version == 'v1':
            happy_flow = ["main_mode_1", "main_mode_2", "main_mode_3", "quick_mode_1_with_group", "quick_mode_2", "delete_ESP","delete_IKE"]
            happy_flow = ["main_mode_1", "main_mode_2", "main_mode_3", "quick_mode_1", "quick_mode_2", "delete_ESP","delete_IKE"]
        else:
            happy_flow = ["SAINIT_SA-KE-NONCE", "AUTH_IDi-AUTH-SA-TSi-TSr", "CHILDSA_SA-NONCE-TSi-TSr", "CHILDSA_RekeyIKE-KE-NONCE",  "CHILDSA_RekeySA-SA-NONCE-TSi-TSr", "INFO_DelChild", "INFO_DelIKE"]

    states = []

    paths = glob.glob(f"{dir1}/*.dot")

    model_path = os.path.join(dir1,'learned_model.pkl')

    with open(model_path,'rb') as f:
        learned_model = pickle.load(f)

    print(learned_model)

    states.append(learned_model.initial_state.state_id)
    for letter in happy_flow:
        learned_model.step(letter)
        states.append(learned_model.current_state.state_id)

    print(states)


    for path in paths:

        if os.path.basename(path)[-6:-4] == 'kp':
            continue

        save_path = path[:-4] + '_kp.dot'
        # print(save_path)
        with open(path, 'r') as f:
            dot = f.read()
        for idx in range(len(states) - 1):
            s0 = states[idx]
            s1 = states[idx+1]
            str1 = f"{s0} -> {s1}  ["
            str2 = f"{s0} -> {s1}  [color = red,"
            if str2 not in dot:
                dot = dot.replace(str1,str2)

        with open(save_path,'w') as f:
            f.write(dot)

        # break


def config_vaild(config):

    
    vaild_key = {"version":['v1','v2'],"local_ip":str,"remote_ip":str,"psk":str,"iface":str,"out_dir":str,"alphabet":list,"IPSEC_CONFIG":{"IKE_attr_values":{"ENCR":str}},"alpahbet_map":list,"must_query_result":dict,"restart":['True','False'],"wait_time":int}


# 自定义过滤器类
class DynamicFilter(logging.Filter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filter_out_library = True

    def filter(self, record):
        if self.filter_out_library:
            return not record.name.startswith('111')
        return True





def filter_logs(input_file, output_file, keyword):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            # 过滤掉包含特定关键字的日志条目
            if keyword in line:
                outfile.write(line.replace(keyword,""))

def start_filtering(input_file, output_file, keyword, interval):
    while True:
        filter_logs(input_file, output_file, keyword)
        time.sleep(interval)  # 每隔指定秒数重新过滤一次




keyword = "ipsec_learning_namespace"
def logger_str(str1):
    str1 = f'ipsec_learning_namespace: {str1}'
    return str1

