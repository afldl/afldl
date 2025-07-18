#!/usr/bin/python
# -*- coding: UTF-8 -*-
import argparse, asyncio, io, os, enum, struct, collections, hashlib, ipaddress, socket, random, sys, socket
import time, math
import copy
import pproxy
from pesp4 import enums, message, crypto
from scapy.all import *
from pesp4 import default
from pesp4.__doc__ import *
from pesp4.IKEfuzzer.IKE_fuzzer import *
import utils

class MyThread(threading.Thread):
    def __init__(self, func, kwargs):
        super(MyThread, self).__init__()
        self.func = func
        self.kwargs = kwargs

    def run(self):
        self.result = self.func(**self.kwargs)

    def get_result(self):
        threading.Thread.join(self)  # 等待线程执行完毕
        try:
            return self.result
        except Exception:
            return None

class State(enum.Enum):
    INITIAL = 0
    SA_SENT = 1
    ESTABLISHED = 2
    DELETED = 3
    KE_SENT = 4
    HASH_SENT = 5
    AUTH_SET = 6
    CONF_SENT = 7
    CHILD_SA_SENT = 8


class ChildSa:
    def __init__(self, spi_in, spi_out, crypto_in, crypto_out, my_nonce, peer_nonce, target_IP):
        self.spi_in = spi_in
        self.spi_out = spi_out
        self.crypto_in = crypto_in
        self.crypto_out = crypto_out
        self.msgid_in = 1
        self.msgid_out = 1
        self.msgwin_in = set()
        self.child = None
        self.my_nonce = my_nonce
        self.peer_nonce = peer_nonce
        self.target_IP = target_IP

    def incr_msgid_out(self):
        self.msgid_out += 1


class IKEv1_client():
    def __init__(self, my_IP, target_IP, iface, passwd='123456', sessions={},  p12_cert=None, public_cert=None,
                 client_private_key_file=None, IKE_attr_values=default.IKE_attr_values,
                 ESP_attr_values=default.ESP_attr_values, ESP_T_id=default.ESP_T_id,AH_attr_values=default.AH_attr_values,AH_T_id=default.AH_T_id,timeout=1,quick_mode_group_config = None):
        
        self.quick_mode_group_config = quick_mode_group_config
        # print(quick_mode_group_config)
        
        self.my_IP = my_IP
        self.target_IP = target_IP
        self.iface = iface
        self.passwd = passwd
        self.sessions = sessions
        self.AH_attr_values = AH_attr_values
        self.AH_T_id = AH_T_id

        self.my_spi = os.urandom(8)
        self.peer_spi = b"\x00" * 8
        self.peer_msgid = 0
        self.crypto = None
        self.peer_crypto = None
        self.my_nonce = os.urandom(32)
        self.peer_nonce = None
        self.state = State.INITIAL
        self.IKE_attr_values = IKE_attr_values
        self.my_public_key, self.dh_a = crypto.DH_create_my_public_key(
                    self.IKE_attr_values[enums.TransformAttr.DH])
        self.ESP_attr_values = ESP_attr_values
        self.ESP_T_id = ESP_T_id
        self.NAT_flag = 0
        self.child_sa = []
        
        self.transform = None
        self.receive_main_mode_3_flag = False  
        
        self.p12_cert = p12_cert
        self.p12_cert_passwd = b""
        self.public_cert = public_cert
        self.client_private_key_file = client_private_key_file
        if self.p12_cert is not None:
            self.user_provided_auth_mode = enums.AuthId_1.RSA  
        else:
            self.user_provided_auth_mode = enums.AuthId_1.PSK
        self.receive_IKE_message_list = []
        self.my_MAC = None
        self.target_MAC = None
        self.packets_buffer = []
        self.fuzz_plain_bytes = b''
        self.current_fuzz_plain = b''
        self.current_abstractinput = None
        self.timeout=timeout
        self.fuzzing = False
        self.fuzz_replay_mode = False
        self.fuzz_replay_data = None
        self.fuzzer = IKE_fuzzer()
        self.esp_dh_a = 3

        


    def response(self, exchange, payloads, message_id=0, *, crypto=None, hashmsg=None, quick_mode_3_flag=False):
        response = message.Message(self.my_spi, self.peer_spi, 0x10, exchange,
                                   enums.MsgFlag.NONE, message_id, payloads)
    
        if self.fuzz_replay_mode:
            self.fuzzer.fuzz_one_message(response)
            
        if self.fuzzing:
            self.fuzzer.fuzz_one_message(response)
            self.current_abstractinput = f'{self.current_abstractinput}*'
        self.current_fuzz_plain = response.to_bytes(crypto=None)
        self.fuzz_plain_bytes += struct.pack('>H', len(self.current_fuzz_plain))
        self.fuzz_plain_bytes += self.current_fuzz_plain
        
        # self.current_abstractinput = ''
        # if response.exchange == enums.Exchange.IDENTITY_1:
        #     self.current_abstractinput += 'Main_'
        # elif response.exchange == enums.Exchange.IKE_AGGRESIVE_1:
        #     self.current_abstractinput += 'Aggr_'
        # elif response.exchange == enums.Exchange.QUICK_1:
        #     self.current_abstractinput += 'Quick_'
        # elif response.exchange == enums.Exchange.INFORMATIONAL_1:
        #     self.current_abstractinput += 'Info_'
        # for pd in response.payloads:
        #     self.current_abstractinput += (str(pd.type).split('Payload.')[1] + '-')
        # self.current_abstractinput = self.current_abstractinput.strip('-')
            
        if hashmsg and crypto:
            buf = (b'' if hashmsg is True else hashmsg) + message.Message.encode_payloads(response.payloads)
            hash_r = self.crypto.prf.prf(self.skeyid_a, message_id.to_bytes(4, 'big') + buf)
            if quick_mode_3_flag:
                hash_r = self.crypto.prf.prf(self.skeyid_a, bytes([0]) + message_id.to_bytes(4, 'big') + buf)
            response.payloads.insert(0, message.PayloadHASH_1(hash_r))

        return response.to_bytes(crypto=crypto), message_id

    #-----------------------------------------------------------------------------------------------------------------
    # The functions to send, receive and process message
    #-----------------------------------------------------------------------------------------------------------------
    def my_srp1(self, pks, filter, verbose=0):
        try:
            timeout=self.timeout
            iface = self.iface
            filter = "src host %s and " % self.target_IP + filter if filter != "" else "src host %s" % self.target_IP
            # when send and receive IKE, we also sniff ICMP message
            if 'esp' not in filter:  
                filter = f'({filter}) or (src host {self.target_IP} and icmp)'
            for i in range(1):
                task = MyThread(sniff, {"iface": iface, "filter": filter, "timeout": timeout + i * 0.5})
                task.start()
                time.sleep(0.2)
                sendp(pks, iface=iface, verbose=verbose)
                pck = task.get_result()
                self.packets_buffer.append(pks)
                self.packets_buffer.append(pck)
                if len(pck) != 0:
                    return pck
            return None
        except:
            print("Exception in thread. Please restart mapper!")
            print(traceback.print_exc())
            sys.exit(-2)
    
    def reset_packet_buffer(self):
        self.packets_buffer = []
    
    def save_fuzz_plain(self, filename):
        with open(filename, 'wb') as file:
            file.write(self.fuzz_plain_bytes)
        
    def save_pcap(self, pcap_filename_prefix):
        if not os.path.exists(f'{pcap_filename_prefix}.pcap'):
            wrpcap(f'{pcap_filename_prefix}.pcap', self.packets_buffer) 
            return 
        count = 0
        while True:
            count += 1
            if not os.path.exists(f'{pcap_filename_prefix}_{count}.pcap'):
                wrpcap(f'{pcap_filename_prefix}_{count}.pcap', self.packets_buffer)  # save packet just sent
                return

    def sr_IKE(self, data, message_name):
        if len(data) > 1500:
            data = data[:1500]
        if not self.NAT_flag:
            if self.target_MAC is None or self.my_MAC is None:
                send_message = Ether() / IP(src=self.my_IP, dst=self.target_IP) / UDP(sport=500, dport=500) / raw(data)
            else:
                send_message = Ether(src=self.my_MAC, dst=self.target_MAC) / IP(src=self.my_IP, dst=self.target_IP) / UDP(sport=500, dport=500) / raw(data)
            received_message = self.my_srp1(send_message, filter="udp and port 500")
        else:
            send_message = Ether() / IP(dst=self.target_IP) / UDP(sport=4500, dport=4500) / raw(b'\x00' * 4 + data)
            received_message = self.my_srp1(send_message, filter="udp and port 4500")
        if received_message is None:
            return enums.Response.No_response
        return self.process(received_message, message_name)

    # AH or ESP ping
    def sr_ipsec_ping(self, IP_data, child_sa, proto=enums.Protocol.AH, tunnl=False):
        send_message = Ether() / IP_data
        received_message = self.my_srp1(send_message, filter="esp")
        if received_message is None:
            return enums.Response.No_response
        if proto == enums.Protocol.AH:
            sa = SecurityAssociation(AH, spi=struct.unpack('>L', bytes(child_sa.spi_in))[0],
                                 auth_algo=default.auth_algo_map[child_sa.crypto_in.integrity.transform],
                                 auth_key=child_sa.crypto_in.sk_a,
                                 )
        else:
            sa = SecurityAssociation(ESP, spi=struct.unpack('>L', bytes(child_sa.spi_in))[0],
                                 crypt_algo=default.crypt_algo_map[child_sa.crypto_in.cipher.transform],
                                 crypt_key=child_sa.crypto_in.sk_e,
                                 auth_algo=default.auth_algo_map[child_sa.crypto_in.integrity.transform],
                                 auth_key=child_sa.crypto_in.sk_a,
                                 )
        if tunnl:
            sa.tunnel_header = IP(dst=self.my_IP)
        process_ping_packs = []
        for pack in received_message:
            if struct.pack("!L", pack[ESP].spi) == child_sa.spi_in and pack[ESP].seq == child_sa.msgid_in:
                return enums.Response.ESP_reply
            else:
                return enums.Response.wrong_ESP_reply
            # if struct.pack("!L", pack[ESP].spi) == child_sa.spi_in and pack[ESP].seq == child_sa.msgid_in:
            #     c = sa.decrypt(pack[IP])
            #     if c.haslayer(IP):
            #         if c[IP].proto == 1:
            #             if c[ICMP].type == 0:
            #                 process_ping_packs.append(c)
        # if len(process_ping_packs) == 0:
        #     return enums.Response.No_response
        # if len(process_ping_packs) == 1:
        #     child_sa.msgid_in += 1
        #     child_sa.msgid_out += 1
        #     # print("received ping reply")
        #     return enums.Response.ESP_reply
        # else:
        #     print("received more than one ping reply in ESP response!")
        #     return enums.Response.ESP_more


    # process currently received all messages
    def process(self, received_message, message_name):
        for pack in received_message:
            if pack.haslayer(ICMP):
                icmp = pack.getlayer(ICMP)
                if icmp.type == 3: #Destination Unreachable
                    return enums.Response.PortUnreachable
        process_IKE_packs = []
        for pack in received_message:
            if not pack.haslayer(UDP):
                continue
            UDPdata = pack[UDP]
            if UDPdata.sport == 500:
                if bytes(UDPdata.payload)[:8] == self.my_spi:
                    process_IKE_packs.append(bytes(UDPdata.payload))
            elif UDPdata.sport == 4500 and bytes(UDPdata.payload)[:4] == b'\x00' * 4:
                payload = bytes(UDPdata.payload)[4:]
                if payload[:8] == self.my_spi:
                    process_IKE_packs.append(payload)
        if len(process_IKE_packs) != 0:
            results = ''
            for IKE_pack in process_IKE_packs:
                result = self.process_IKE(IKE_pack, message_name)
                if result is not None:
                    return result
                    # results += (str(result) + '-')
            # if len(results) >= 1:
            #     return results.strip('-')
            return enums.Response.Other
        else:
            return enums.Response.No_response
        
        return enums.Response.No_response

    def verify_hash(self, request, quick_mode_flag=False):
        payload_hash = request.payloads.pop(0)
        assert payload_hash.type == enums.Payload.HASH_1
        hash_i = self.crypto.prf.prf(self.skeyid_a,
                                     request.message_id.to_bytes(4, 'big') + message.Message.encode_payloads(
                                         request.payloads))
        if quick_mode_flag:
            hash_i = self.crypto.prf.prf(self.skeyid_a, request.message_id.to_bytes(4, 'big') +
                                         self.my_nonce + message.Message.encode_payloads(request.payloads))

        assert hash_i == payload_hash.data
        
    # process one IKE message
    def process_IKE(self, IKE_data, message_name):
        for receive_message in self.receive_IKE_message_list:  # 重放检查
            if IKE_data == receive_message:
                return None
        self.receive_IKE_message_list.append(IKE_data)
        stream = io.BytesIO(bytes(IKE_data))
        resp = message.Message.parse(stream)
        try:
            resp.parse_payloads(stream, crypto=self.crypto)
        except:
            return enums.Response.Error
        if resp.exchange == enums.Exchange.IDENTITY_1 and resp.get_payload(enums.Payload.SA_1):
            if self.peer_spi != b'\x00' * 8:
                print("another main_mode_1 packets")
                sys.exit()
            self.peer_spi = resp.spi_r
            sas = [x for x in resp.payloads if x.type == enums.Payload.SA_1]
            if len(sas) > 1:
                return enums.Response.multi_sa_main_mode_1
            request_payload_sa = resp.get_payload(enums.Payload.SA_1) 
            if not hasattr(self, "sa_bytes"):
                self.sa_bytes = request_payload_sa.to_bytes()
            self.transform = request_payload_sa.proposals[0].transforms[0].values
            self.auth_mode = self.transform[enums.TransformAttr.AUTH]
            del request_payload_sa.proposals[0].transforms[1:]  # 不知道删这个对前面的赋值有无影响
            self.state = State.SA_SENT
            return enums.Response.main_mode_1
        elif resp.exchange == enums.Exchange.IDENTITY_1 and resp.get_payload(enums.Payload.KE_1):
            if not hasattr(self, "dh_a"):
                return enums.Response.main_mode_2_half
            self.peer_public_key = resp.get_payload(enums.Payload.KE_1).ke_data
            self.shared_secret = crypto.DH_caculate_shared_secret(self.transform[enums.TransformAttr.DH], self.dh_a,
                                                                  self.peer_public_key)
            self.peer_nonce = resp.get_payload(enums.Payload.NONCE_1).nonce
            if self.transform[enums.TransformAttr.ENCR] == enums.EncrId_1.AES_CBC:
                cipher = crypto.Cipher(self.transform[enums.TransformAttr.ENCR],
                                       self.transform[enums.TransformAttr.KEY_LENGTH])
            elif self.transform[enums.TransformAttr.ENCR] == enums.EncrId_1.DES_CBC:
                cipher = crypto.Cipher(self.transform[enums.TransformAttr.ENCR], 64)
            elif self.transform[enums.TransformAttr.ENCR] == enums.EncrId_1._3DES_CBC:
                cipher = crypto.Cipher(self.transform[enums.TransformAttr.ENCR], 192)
            prf = crypto.Prf(self.transform[enums.TransformAttr.HASH])
            if self.user_provided_auth_mode == enums.AuthId_1.RSA:
                self.skeyid = prf.prf(self.my_nonce + self.peer_nonce, self.shared_secret)
            else:
                self.skeyid = prf.prf(self.passwd.encode(), self.my_nonce + self.peer_nonce)
            self.skeyid_d = prf.prf(self.skeyid, self.shared_secret + self.my_spi + self.peer_spi + bytes([0]))
            self.skeyid_a = prf.prf(self.skeyid,
                                    self.skeyid_d + self.shared_secret + self.my_spi + self.peer_spi + bytes([1]))
            self.skeyid_e = prf.prf(self.skeyid,
                                    self.skeyid_a + self.shared_secret + self.my_spi + self.peer_spi + bytes([2]))
            if len(self.skeyid_e) < cipher.key_size:
                key = b''
                K = bytes([0])
                for i in range(5):
                    K = prf.prf(self.skeyid_e, K)
                    key += K
                self.skeyid_e = key
            iv = prf.hasher(self.my_public_key + self.peer_public_key).digest()[:cipher.block_size]
            self.crypto = crypto.Crypto(cipher, self.skeyid_e[:cipher.key_size], prf=prf, iv=iv) 
            self.state = State.KE_SENT
            return enums.Response.main_mode_2
        elif resp.exchange == enums.Exchange.IDENTITY_1 and resp.get_payload(enums.Payload.ID_1):
            if resp.flag == 0x00:
                return enums.Response.plain_main_mode_3
            if self.auth_mode == enums.AuthId_1.RSA:
                self.state = State.HASH_SENT
                self.receive_main_mode_3_flag = True
                return enums.Response.main_mode_3
            else:
                response_payload_id = resp.get_payload(enums.Payload.ID_1)
                prf = self.crypto.prf
                hash_r = prf.prf(self.skeyid, self.peer_public_key + self.my_public_key + self.peer_spi + self.my_spi +
                                 self.sa_bytes + response_payload_id.to_bytes())
                assert hash_r == resp.get_payload(enums.Payload.HASH_1).data, 'Authentication Failed'
                self.state = State.HASH_SENT
                self.receive_main_mode_3_flag = True
                return enums.Response.main_mode_3
        elif resp.exchange == enums.Exchange.QUICK_1 and len(resp.payloads) == 1:
            if resp.payloads[0].type == enums.Payload.HASH_1:
                self.state = State.ESTABLISHED
                return enums.Response.Error  # 有待商榷
        elif resp.exchange == enums.Exchange.QUICK_1 and len(resp.payloads) == 2:
            if resp.get_payload(enums.Payload.HASH_1) and resp.get_payload(enums.Payload.NOTIFY_1):
                return enums.Response.quick_mode_2
        elif resp.exchange == enums.Exchange.QUICK_1:
            payload_nonce = resp.get_payload(enums.Payload.NONCE_1)
            peer_nonce = payload_nonce.nonce
            my_nonce = self.my_nonce
            chosen_proposal = resp.get_payload(enums.Payload.SA_1).proposals[0]
            del chosen_proposal.transforms[1:]
            peer_spi = chosen_proposal.spi
            if not hasattr(self, "esp_spi"):
                self.esp_spi = os.urandom(4)
            my_spi = self.esp_spi
            transform = chosen_proposal.transforms[0].values
            if resp.get_payload(enums.Payload.KE_1):
                self.esp_peer_public_key = resp.get_payload(enums.Payload.KE_1).ke_data
                self.esp_shared_secret = crypto.DH_caculate_shared_secret(transform[enums.ESPAttr.GRP_DESC], self.esp_dh_a,
                                                                  self.esp_peer_public_key)
            if chosen_proposal.protocol == enums.Protocol.AH:
                cipher = None
            else:
                if chosen_proposal.transforms[0].id == enums.EncrId.ENCR_3DES:
                    cipher = crypto.Cipher(chosen_proposal.transforms[0].id, 192)
                elif chosen_proposal.transforms[0].id == enums.EncrId.ENCR_DES:
                    cipher = crypto.Cipher(chosen_proposal.transforms[0].id, 64)
                else:
                    cipher = crypto.Cipher(chosen_proposal.transforms[0].id, transform[enums.ESPAttr.KEY_LENGTH])
            integ = crypto.Integrity(transform[enums.ESPAttr.AUTH])
            if cipher is None:
                keymat_fmt = struct.Struct('>{0}s{1}s'.format(0, integ.key_size))
            else:
                keymat_fmt = struct.Struct('>{0}s{1}s'.format(cipher.key_size, integ.key_size))
            if resp.get_payload(enums.Payload.KE_1):
                keymat = self.crypto.prf.prfplus(self.skeyid_d,
                                                 self.esp_shared_secret + bytes([chosen_proposal.protocol]) + peer_spi + my_nonce + peer_nonce,
                                                 False)
                sk_ei, sk_ai = keymat_fmt.unpack(bytes(next(keymat) for _ in range(keymat_fmt.size)))
                keymat = self.crypto.prf.prfplus(self.skeyid_d,
                                                 self.esp_shared_secret + bytes([chosen_proposal.protocol]) + my_spi + my_nonce + peer_nonce, False)
                sk_er, sk_ar = keymat_fmt.unpack(bytes(next(keymat) for _ in range(keymat_fmt.size)))
            else:
                keymat = self.crypto.prf.prfplus(self.skeyid_d,
                                                 bytes([chosen_proposal.protocol]) + peer_spi + my_nonce + peer_nonce,
                                                 False)
                sk_ei, sk_ai = keymat_fmt.unpack(bytes(next(keymat) for _ in range(keymat_fmt.size)))
                keymat = self.crypto.prf.prfplus(self.skeyid_d,
                                                 bytes([chosen_proposal.protocol]) + my_spi + my_nonce + peer_nonce,
                                                 False)
                sk_er, sk_ar = keymat_fmt.unpack(bytes(next(keymat) for _ in range(keymat_fmt.size)))
            crypto_out = crypto.Crypto(cipher, sk_ei, integ, sk_ai)
            crypto_in = crypto.Crypto(cipher, sk_er, integ, sk_ar)
            child_sa = ChildSa(my_spi, peer_spi, crypto_in, crypto_out, my_nonce, peer_nonce, self.target_IP)
            self.sessions[my_spi] = child_sa
            for old_child_sa in self.child_sa:
                old_child_sa.child = child_sa
            self.child_sa.append(child_sa)
            self.state = State.CHILD_SA_SENT
            return enums.Response.quick_mode_1
        elif resp.exchange == enums.Exchange.INFORMATIONAL_1:
            try:
                if self.crypto and resp.flag:
                    self.verify_hash(resp)
            except:
                print("verify_hash Error!")
                return enums.Response.Error
            response_payloads = []
            delete_payload = resp.get_payload(enums.Payload.DELETE_1)
            notify_payload = resp.get_payload(enums.Payload.NOTIFY_1)
            if not resp.payloads:
                pass
            elif delete_payload and delete_payload.protocol == enums.Protocol.IKE:
                self.state = State.DELETED
                response_payloads.append(delete_payload)
                message_id = resp.message_id
                return enums.Response.delete_IKE
            elif delete_payload:
                if message_name != enums.message_name.delete_ESP and message_name != enums.message_name.fuzz_mode:  # 只允许主动删除ESP
                    return None
                spis = []
                for spi in delete_payload.spis:
                    child_sa = next((x for x in self.child_sa if x.spi_out == spi), None)
                    if child_sa:
                        self.child_sa.remove(child_sa)
                        self.sessions.pop(child_sa.spi_in)
                        spis.append(child_sa.spi_in)
                response_payloads.append(message.PayloadDELETE_1(delete_payload.doi, delete_payload.protocol, spis))
                message_id = resp.message_id
                return enums.Response.delete_ESP
            elif notify_payload:
                return enums.Notify(notify_payload.notify)
            else:
                print(f'unhandled informational {resp!r}')
                return enums.Response.Other
        if resp.exchange == enums.Exchange.IKE_AGGRESIVE_1:
            self.peer_spi = resp.spi_r
            if resp.get_payload(enums.Payload.SA_1):
                request_payload_sa = resp.get_payload(enums.Payload.SA_1)
                if not hasattr(self, "sa_bytes"):
                    self.sa_bytes = request_payload_sa.to_bytes()
                self.transform = request_payload_sa.proposals[0].transforms[0].values
                self.auth_mode = self.transform[enums.TransformAttr.AUTH]
                del request_payload_sa.proposals[0].transforms[1:]
            self.peer_public_key = resp.get_payload(enums.Payload.KE_1).ke_data
            self.shared_secret = crypto.DH_caculate_shared_secret(self.transform[enums.TransformAttr.DH], self.dh_a,
                                                                  self.peer_public_key)
            self.peer_nonce = resp.get_payload(enums.Payload.NONCE_1).nonce
            if self.transform[enums.TransformAttr.ENCR] == enums.EncrId_1.AES_CBC:
                cipher = crypto.Cipher(self.transform[enums.TransformAttr.ENCR],
                                       self.transform[enums.TransformAttr.KEY_LENGTH])
            elif self.transform[enums.TransformAttr.ENCR] == enums.EncrId_1.DES_CBC:
                cipher = crypto.Cipher(self.transform[enums.TransformAttr.ENCR], 64)
            elif self.transform[enums.TransformAttr.ENCR] == enums.EncrId_1._3DES_CBC:
                cipher = crypto.Cipher(self.transform[enums.TransformAttr.ENCR], 192)
            prf = crypto.Prf(self.transform[enums.TransformAttr.HASH])
            if self.user_provided_auth_mode == enums.AuthId_1.RSA:
                self.skeyid = prf.prf(self.my_nonce + self.peer_nonce, self.shared_secret)
            else:
                self.skeyid = prf.prf(self.passwd.encode(), self.my_nonce + self.peer_nonce)
            self.skeyid_d = prf.prf(self.skeyid, self.shared_secret + self.my_spi + self.peer_spi + bytes([0]))
            self.skeyid_a = prf.prf(self.skeyid,
                                    self.skeyid_d + self.shared_secret + self.my_spi + self.peer_spi + bytes([1]))
            self.skeyid_e = prf.prf(self.skeyid,
                                    self.skeyid_a + self.shared_secret + self.my_spi + self.peer_spi + bytes([2]))
            if len(self.skeyid_e) < cipher.key_size:
                key = b''
                K = bytes([0])
                for i in range(5):
                    K = prf.prf(self.skeyid_e, K)
                    key += K
                self.skeyid_e = key
            iv = prf.hasher(self.my_public_key + self.peer_public_key).digest()[:cipher.block_size]
            self.crypto = crypto.Crypto(cipher, self.skeyid_e[:cipher.key_size], prf=prf, iv=iv)
            self.state = State.KE_SENT
            return enums.Response.aggressive_mode_1
        return enums.Response.Other

    #-----------------------------------------------------------------------------------------------------------------
    # The functions to Instantiate a symbol
    #-----------------------------------------------------------------------------------------------------------------
    def send_main_mode_1(self):
        values = copy.deepcopy(self.IKE_attr_values)
        values[enums.TransformAttr.AUTH] = self.user_provided_auth_mode
        values[enums.TransformAttr.LIFETYPE] = 1  # second
        # values[enums.TransformAttr.DURATION] = 28800
        values[enums.TransformAttr.DURATION] = 3600
        my_IKE_T_payload = message.Transform_1(1, enums.Protocol.IKE, values)
        my_IKE_P_payload = message.Proposal_1(num=1, protocol=enums.Protocol.IKE, spi=b'',
                                              transforms=[my_IKE_T_payload])
        # vendor_1 = message.PayloadVENDOR_1(bytes.fromhex("a9b9b1034f7e50a2513b47b100bb85a9"))
        # vendor_1 = message.PayloadVENDOR_1(bytes.fromhex("01528bbbc00696121849ab9a1c5b2a5100000001"))
        # vendor_2 = message.PayloadVENDOR_1(bytes.fromhex("1e2b516905991c7d7c96fcbfb587e46100000009"))
        # vendor_3 = message.PayloadVENDOR_1(bytes.fromhex("4a131c81070358455c5728f20e95452f"))
        # vendor_4 = message.PayloadVENDOR_1(bytes.fromhex("90cb80913ebb696e086381b5ec427b1f"))
        # vendor_5 = message.PayloadVENDOR_1(bytes.fromhex("4048b7d56ebce88525e7de7f00d6c2d3"))
        # vendor_6 = message.PayloadVENDOR_1(bytes.fromhex("fb1de3cdf341b7ea16b7e5be0855f120"))
        # vendor_7 = message.PayloadVENDOR_1(bytes.fromhex("26244d38eddb61b3172a36e3d0cfb819"))
        # vendor_8 = message.PayloadVENDOR_1(bytes.fromhex("e3a5966a76379fe707228231e5ce8652"))
        my_SA_payload = message.PayloadSA_1(doi=1, situation=1, proposals=[my_IKE_P_payload])
        self.sa_bytes = my_SA_payload.to_bytes()
        response_payloads = [my_SA_payload
                            #  ,vendor_1
            # , vendor_1, vendor_2, vendor_3, vendor_4, vendor_5, vendor_6, vendor_7, vendor_8
                             ]
        main_mode_1_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, crypto=self.crypto, hashmsg=True)
        return self.sr_IKE(main_mode_1_data, enums.message_name.main_mode_1)
    
    def send_multi_sa_main_mode_1(self):
        values = copy.deepcopy(self.IKE_attr_values)
        values[enums.TransformAttr.AUTH] = self.user_provided_auth_mode
        values[enums.TransformAttr.LIFETYPE] = 1  # second
        values[enums.TransformAttr.DURATION] = 28800
        my_IKE_T_payload = message.Transform_1(1, enums.Protocol.IKE, values)
        my_IKE_P_payload = message.Proposal_1(num=1, protocol=enums.Protocol.IKE, spi=b'',
                                              transforms=[my_IKE_T_payload])
        vendor_1 = message.PayloadVENDOR_1(bytes.fromhex("01528bbbc00696121849ab9a1c5b2a5100000001"))
        vendor_2 = message.PayloadVENDOR_1(bytes.fromhex("1e2b516905991c7d7c96fcbfb587e46100000009"))
        vendor_3 = message.PayloadVENDOR_1(bytes.fromhex("4a131c81070358455c5728f20e95452f"))
        vendor_4 = message.PayloadVENDOR_1(bytes.fromhex("90cb80913ebb696e086381b5ec427b1f"))
        vendor_5 = message.PayloadVENDOR_1(bytes.fromhex("4048b7d56ebce88525e7de7f00d6c2d3"))
        vendor_6 = message.PayloadVENDOR_1(bytes.fromhex("fb1de3cdf341b7ea16b7e5be0855f120"))
        vendor_7 = message.PayloadVENDOR_1(bytes.fromhex("26244d38eddb61b3172a36e3d0cfb819"))
        vendor_8 = message.PayloadVENDOR_1(bytes.fromhex("e3a5966a76379fe707228231e5ce8652"))
        my_SA_payload = message.PayloadSA_1(doi=1, situation=1, proposals=[my_IKE_P_payload])
        self.sa_bytes = my_SA_payload.to_bytes()
        response_payloads = [my_SA_payload, my_SA_payload
            , vendor_1, vendor_2, vendor_3, vendor_4, vendor_5, vendor_6, vendor_7, vendor_8
                             ]
        main_mode_1_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, crypto=self.crypto, hashmsg=True)
        return self.sr_IKE(main_mode_1_data, enums.message_name.main_mode_1)

    def send_aggressive_mode_1(self):
        values = copy.deepcopy(self.IKE_attr_values)
        values[enums.TransformAttr.AUTH] = self.user_provided_auth_mode
        values[enums.TransformAttr.LIFETYPE] = 1  # second
        values[enums.TransformAttr.DURATION] = 28800
        my_IKE_T_payload = message.Transform_1(1, enums.Protocol.IKE, values)  
        my_IKE_P_payload = message.Proposal_1(num=1, protocol=enums.Protocol.IKE, spi=b'',
                                              transforms=[my_IKE_T_payload]) 
        vendor_1 = message.PayloadVENDOR_1(bytes.fromhex("01528bbbc00696121849ab9a1c5b2a5100000001"))
        vendor_2 = message.PayloadVENDOR_1(bytes.fromhex("1e2b516905991c7d7c96fcbfb587e46100000009"))
        vendor_3 = message.PayloadVENDOR_1(bytes.fromhex("4a131c81070358455c5728f20e95452f"))
        vendor_4 = message.PayloadVENDOR_1(bytes.fromhex("90cb80913ebb696e086381b5ec427b1f"))
        vendor_5 = message.PayloadVENDOR_1(bytes.fromhex("4048b7d56ebce88525e7de7f00d6c2d3"))
        vendor_6 = message.PayloadVENDOR_1(bytes.fromhex("fb1de3cdf341b7ea16b7e5be0855f120"))
        vendor_7 = message.PayloadVENDOR_1(bytes.fromhex("26244d38eddb61b3172a36e3d0cfb819"))
        vendor_8 = message.PayloadVENDOR_1(bytes.fromhex("e3a5966a76379fe707228231e5ce8652"))
        my_SA_payload = message.PayloadSA_1(doi=1, situation=1, proposals=[my_IKE_P_payload])
        self.sa_bytes = my_SA_payload.to_bytes()
        try:
            if self.transform is None:
                self.my_public_key, self.dh_a = crypto.DH_create_my_public_key(
                    self.IKE_attr_values[enums.TransformAttr.DH])
            else:
                self.my_public_key, self.dh_a = crypto.DH_create_my_public_key(self.transform[enums.TransformAttr.DH])
        except:
            print('Get DH TransformAttr error, maybe receive other main mode 1 TransformAttr payload!')
            return None

        src_ip_int = struct.unpack("!L", socket.inet_aton(self.my_IP))[0]
        payload_id = message.PayloadID_1(enums.IDType.ID_IPV4_ADDR, struct.pack("!I", src_ip_int))
        self.payload_id = payload_id
        response_payloads = [my_SA_payload,
                             message.PayloadKE_1(self.my_public_key), message.PayloadNONCE_1(self.my_nonce),
                             payload_id
            , vendor_1, vendor_2, vendor_3, vendor_4, vendor_5, vendor_6, vendor_7, vendor_8
                             ]

        aggressive_mode_1_data, message_id = self.response(enums.Exchange.IKE_AGGRESIVE_1, response_payloads, crypto=self.crypto, hashmsg=True)
        return self.sr_IKE(aggressive_mode_1_data, enums.message_name.aggressive_mode_1)

    def send_aggressive_mode_2(self):
        if self.crypto is None:
            aggressive_mode_2_data, message_id = self.response(enums.Exchange.IKE_AGGRESIVE_1, [], crypto=self.crypto)
            return self.sr_IKE(aggressive_mode_2_data, enums.message_name.aggressive_mode_2)
        if not hasattr(self, "payload_id"):
            src_ip_int = struct.unpack("!L", socket.inet_aton(self.my_IP))[0]
            self.payload_id = message.PayloadID_1(enums.IDType.ID_IPV4_ADDR, struct.pack("!I", src_ip_int))
        prf = self.crypto.prf
        hash_i = prf.prf(self.skeyid, self.my_public_key + self.peer_public_key + self.my_spi + self.peer_spi +
                         self.sa_bytes + self.payload_id.to_bytes())
        response_payloads = [message.PayloadHASH_1(hash_i)]
        aggressive_mode_2_data, message_id = self.response(enums.Exchange.IKE_AGGRESIVE_1, response_payloads, crypto=self.crypto)
        return self.sr_IKE(aggressive_mode_2_data, enums.message_name.aggressive_mode_2)

    def send_main_mode_2(self):
        try:
            if self.transform is None:
                self.my_public_key, self.dh_a = crypto.DH_create_my_public_key(
                    self.IKE_attr_values[enums.TransformAttr.DH])
            else:
                self.my_public_key, self.dh_a = crypto.DH_create_my_public_key(self.transform[enums.TransformAttr.DH])
        except:
            print('Get DH TransformAttr error, maybe receive other main mode 1 TransformAttr payload!')
            return None
        # dst_NAT_hash = bytes.fromhex(hashlib.sha1(self.my_spi + self.peer_spi + socket.inet_aton(self.target_IP) + struct.pack(">H", 500)).hexdigest())
        # src_NAT_hash = bytes.fromhex(hashlib.sha1(self.my_spi + self.peer_spi + socket.inet_aton(self.my_IP) + struct.pack(">H", 500)).hexdigest())
        response_payloads = [message.PayloadKE_1(self.my_public_key), message.PayloadNONCE_1(self.my_nonce)
                            #  , message.PayloadNATD_1(dst_NAT_hash), message.PayloadNATD_1(src_NAT_hash)
                             ]
        # main_mode_2_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, crypto=self.crypto, hashmsg=True)
        main_mode_2_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, crypto=None, hashmsg=True)
        return self.sr_IKE(main_mode_2_data, enums.message_name.main_mode_2)
    
    def send_wrong_nonce_main_mode_2(self):
        try:
            if self.transform is None:
                self.my_public_key, self.dh_a = crypto.DH_create_my_public_key(
                    self.IKE_attr_values[enums.TransformAttr.DH])
            else:
                self.my_public_key, self.dh_a = crypto.DH_create_my_public_key(self.transform[enums.TransformAttr.DH])
        except:
            print('Get DH TransformAttr error, maybe receive other main mode 1 TransformAttr payload!')
            return None
        dst_NAT_hash = bytes.fromhex(hashlib.sha1(self.my_spi + self.peer_spi + socket.inet_aton(self.target_IP) + struct.pack(">H", 500)).hexdigest())
        src_NAT_hash = bytes.fromhex(hashlib.sha1(self.my_spi + self.peer_spi + socket.inet_aton(self.my_IP) + struct.pack(">H", 500)).hexdigest())
        wrong_nonce = self.my_nonce[:7] if random.randint(0, 1) == 0 else os.urandom(257)
        response_payloads = [message.PayloadKE_1(self.my_public_key), message.PayloadNONCE_1(wrong_nonce)
                             , message.PayloadNATD_1(dst_NAT_hash), message.PayloadNATD_1(src_NAT_hash)
                             ]
        # main_mode_2_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, crypto=self.crypto, hashmsg=True)
        main_mode_2_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, crypto=None, hashmsg=True)
        return self.sr_IKE(main_mode_2_data, enums.message_name.main_mode_2)

    def send_main_mode_3(self):
        src_ip_int = struct.unpack("!L", socket.inet_aton(self.my_IP))[0]
        payload_id = message.PayloadID_1(enums.IDType.ID_IPV4_ADDR, struct.pack("!I", src_ip_int))
        if self.crypto is None:
            main_mode_3_data, message_id = self.response(enums.Exchange.IDENTITY_1, [payload_id], crypto=self.crypto)
            return self.sr_IKE(main_mode_3_data, enums.message_name.main_mode_3)
        prf = self.crypto.prf
        hash_i = prf.prf(self.skeyid, self.my_public_key + self.peer_public_key + self.my_spi + self.peer_spi +
                         self.sa_bytes + payload_id.to_bytes())
        response_payloads = [payload_id, message.PayloadHASH_1(hash_i)]
        if self.receive_main_mode_3_flag:
            main_mode_3_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, random.randrange(1 << 32),
                                             crypto=self.crypto)
        else:
            main_mode_3_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, crypto=self.crypto)
        return self.sr_IKE(main_mode_3_data, enums.message_name.main_mode_3)

    def send_main_mode_3_cert(self):
        with open(self.public_cert, 'rb') as f:
            x = X509_Cert(f.read())
            tbs = x.tbsCertificate
            ID_data = b''
            ID_data_length = 0
            for i in range(len(tbs.subject)):
                ID_data = ID_data + bytes(tbs.subject[i])
                ID_data_length = ID_data_length + len(plain_str(tbs.subject[i].rdn[0].value.val)) + 11
            temp = str(format(ID_data_length, '02x'))

            total_length = bytes().fromhex(temp)
            ID_data = b'\x30' + total_length + ID_data
        payload_id = message.PayloadID_1(enums.IDType.ID_FQDN, b"*.a.a")
        if self.crypto is None:
            main_mode_3_data = self.response(enums.Exchange.IDENTITY_1, [payload_id], crypto=self.crypto)
            return enums.Response.No_response
        prf = self.crypto.prf
        hash_i = prf.prf(self.skeyid, self.my_public_key + self.peer_public_key + self.my_spi + self.peer_spi +
                         self.sa_bytes + payload_id.to_bytes())
        with open(self.public_cert, 'rb') as f:
            x = f.read()
            CERT_data = b'\x04' + bytes(x)
        with open("./hash_i.bin", "wb") as f:
            f.write(hash_i)
        p = subprocess.Popen("openssl rsautl -sign -inkey " + self.client_private_key_file + "  -out output.bin -pkcs -in hash_i.bin ", shell=True)
        p.wait()
        with open("./output.bin", "rb") as f:
            signature = f.read()
        response_payloads = [payload_id, message.PayloadCert_1(CERT_data), message.PayloadSignature_1(signature)]
        if self.receive_main_mode_3_flag:
            main_mode_3_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, random.randrange(1 << 32),
                                             crypto=self.crypto)
        else:
            main_mode_3_data, message_id = self.response(enums.Exchange.IDENTITY_1, response_payloads, crypto=self.crypto)
        return self.sr_IKE(main_mode_3_data, enums.message_name.main_mode_3)

    def send_quick_mode_1(self):

        map ={
                "TUNNEL" : enums.EncModeId_1.TUNNEL,
                "TRNS" : enums.EncModeId_1.TRNS
        }
        self.esp_spi = os.urandom(4)
        values = self.ESP_attr_values


        if self.quick_mode_group_config != None:
            values[enums.ESPAttr.ENC_MODE] = map[self.quick_mode_group_config['ENC_MODE']]
            values[enums.ESPAttr.LIFE_TYPE] = self.quick_mode_group_config['LIFE_TYPE']  # second
            values[enums.ESPAttr.DURATION] = self.quick_mode_group_config['DURATION']
        else:
            values[enums.ESPAttr.LIFE_TYPE] = 1  # second
            values[enums.ESPAttr.DURATION] = 3600
            # values[enums.ESPAttr.DURATION] = 43200

            values[enums.ESPAttr.ENC_MODE] = enums.EncModeId_1.TUNNEL
            


        # values[enums.ESPAttr.ENC_MODE] = enums.EncModeId_1.TRNS
        my_ESP_T_payload = message.Transform_1(1, self.ESP_T_id, values)  # 这里与之前IKE不同
        # my_ESP_T_payload = message.Transform_1(1, 0x17, values) #libreswan bug
        my_ESP_P_payload = message.Proposal_1(num=1, protocol=enums.Protocol.ESP, spi=self.esp_spi,  # 这里写死了ESP
                                              transforms=[my_ESP_T_payload])  # spi是空字符串
        src_ip_int = struct.unpack("!L", socket.inet_aton(self.my_IP))[0]
        dst_ip_int = struct.unpack("!L", socket.inet_aton(self.target_IP))[0]
        ip_0_int = struct.unpack("!L", socket.inet_aton("0.0.0.0"))[0]
        # ip_0_int = struct.unpack("!L", socket.inet_aton("0.0.0.0"))[0]
        # src_ip_int = struct.unpack("!L", socket.inet_aton(self.my_IP))[0]
        # dst_ip_int = struct.unpack("!L", socket.inet_aton("192.168.3.0"))[0]
        
        if self.quick_mode_group_config != None and self.quick_mode_group_config['PORT'] == 1701:
            # print("winserver")
            response_payloads = [message.PayloadSA_1(doi=1, situation=1, proposals=[my_ESP_P_payload]),
                                message.PayloadNONCE_1(self.my_nonce),
                                message.PayloadID_1(id_type=1, id_data=struct.pack("!I", src_ip_int),
                                                    prot=enums.IpProto.UDP.value, port=self.quick_mode_group_config['PORT']),  # Strongswan, Libreswan
                                message.PayloadID_1(id_type=1, id_data=struct.pack("!I", dst_ip_int),
                                                    prot=enums.IpProto.UDP.value, port=self.quick_mode_group_config['PORT'])]  #winserver
        else:
            response_payloads = [message.PayloadSA_1(doi=1, situation=1, proposals=[my_ESP_P_payload]),
                                message.PayloadNONCE_1(self.my_nonce),
                                message.PayloadID_1(id_type=1, id_data=struct.pack("!I", src_ip_int),
                                                    prot=enums.IpProto.ANY.value, port=0),  # Strongswan, Libreswan
                                message.PayloadID_1(id_type=1, id_data=struct.pack("!I", dst_ip_int),
                                                    prot=enums.IpProto.ANY.value, port=0)]  # Strongswan, Libreswan   


        quick_mode_1_data, message_id = self.response(enums.Exchange.QUICK_1, response_payloads, 1,
                                          crypto=self.crypto, hashmsg=True)

        return self.sr_IKE(quick_mode_1_data, enums.message_name.quick_mode_1)
    
    def send_wrong_order_quick_mode_1(self):
        self.esp_spi = os.urandom(4)
        values = self.ESP_attr_values
        values[enums.ESPAttr.LIFE_TYPE] = 1  # second
        values[enums.ESPAttr.DURATION] = 3600
        values[enums.ESPAttr.ENC_MODE] = enums.EncModeId_1.TUNNEL
        my_ESP_T_payload = message.Transform_1(1, self.ESP_T_id, values)  # 这里与之前IKE不同
        # my_ESP_T_payload = message.Transform_1(1, 0x17, values) #libreswan bug
        my_ESP_P_payload = message.Proposal_1(num=1, protocol=enums.Protocol.ESP, spi=self.esp_spi,  # 这里写死了ESP
                                              transforms=[my_ESP_T_payload])  # spi是空字符串
        src_ip_int = struct.unpack("!L", socket.inet_aton(self.my_IP))[0]
        dst_ip_int = struct.unpack("!L", socket.inet_aton(self.target_IP))[0]
        ip_0_int = struct.unpack("!L", socket.inet_aton("0.0.0.0"))[0]
        response_payloads = [message.PayloadNONCE_1(self.my_nonce),
                             message.PayloadID_1(id_type=1, id_data=struct.pack("!I", src_ip_int),
                                                 prot=enums.IpProto.ANY.value, port=0),  # Strongswan, Libreswan
                             message.PayloadID_1(id_type=1, id_data=struct.pack("!I", dst_ip_int),
                                                 prot=enums.IpProto.ANY.value, port=0),
                             message.PayloadSA_1(doi=1, situation=1, proposals=[my_ESP_P_payload])]  # Strongswan, Libreswan
        
        quick_mode_1_data, message_id = self.response(enums.Exchange.QUICK_1, response_payloads, 1,
                                          crypto=self.crypto, hashmsg=True)

        return self.sr_IKE(quick_mode_1_data, enums.message_name.quick_mode_1)

    def send_quick_mode_1_with_group(self):
        map ={
                "TUNNEL" : enums.EncModeId_1.TUNNEL,
                "TRNS" : enums.EncModeId_1.TUNNEL
        }
        self.esp_spi = os.urandom(4)
        values = self.ESP_attr_values
        if self.quick_mode_group_config != None:
            values[enums.ESPAttr.GRP_DESC] = self.quick_mode_group_config['GRP_DESC'] # modp 1024
            # values[enums.ESPAttr.GRP_DESC] = 5 # modp 1024
            # values[enums.ESPAttr.ENC_MODE] = enums.EncModeId_1.TRNS
            values[enums.ESPAttr.ENC_MODE] = map[self.quick_mode_group_config['ENC_MODE']]
            values[enums.ESPAttr.LIFE_TYPE] = self.quick_mode_group_config['LIFE_TYPE']  # second
            values[enums.ESPAttr.DURATION] = self.quick_mode_group_config['DURATION']
            # values[enums.ESPAttr.DURATION] = 43200
        else:
            values[enums.ESPAttr.GRP_DESC] = 2 # modp 1024
            # values[enums.ESPAttr.GRP_DESC] = 5 # modp 1024
            # values[enums.ESPAttr.ENC_MODE] = enums.EncModeId_1.TRNS
            values[enums.ESPAttr.ENC_MODE] = enums.EncModeId_1.TUNNEL
            values[enums.ESPAttr.LIFE_TYPE] = 1  # second
            values[enums.ESPAttr.DURATION] = 3600
            # values[enums.ESPAttr.DURATION] = 43200


        self.esp_my_public_key, self.esp_dh_a = crypto.DH_create_my_public_key(values[enums.ESPAttr.GRP_DESC])
        my_ESP_T_payload = message.Transform_1(1, self.ESP_T_id, values)  # 这里与之前IKE不同
        my_ESP_P_payload = message.Proposal_1(num=0, protocol=enums.Protocol.ESP, spi=self.esp_spi,  # 这里写死了ESP
                                              transforms=[my_ESP_T_payload])  # spi是空字符串
        src_ip_int = struct.unpack("!L", socket.inet_aton(self.my_IP))[0]
        dst_ip_int = struct.unpack("!L", socket.inet_aton(self.target_IP))[0]
        ip_0_int = struct.unpack("!L", socket.inet_aton("0.0.0.0"))[0]
        # ip_0_int = struct.unpack("!L", socket.inet_aton("15.15.15.0"))[0]

        response_payloads = [message.PayloadSA_1(doi=1, situation=1, proposals=[my_ESP_P_payload]),
                             message.PayloadNONCE_1(self.my_nonce),
                             message.PayloadKE_1(self.esp_my_public_key),
                             message.PayloadID_1(id_type=4, id_data=struct.pack("!I", ip_0_int) * 2,  # ip_sub_net 0.0.0.0/0.0.0.0
                                                 prot=enums.IpProto.ANY.value, port=0),
                             message.PayloadID_1(id_type=4, id_data=struct.pack("!I", ip_0_int) * 2,
                                                 prot=enums.IpProto.ANY.value, port=0)]
        quick_mode_1_data, message_id = self.response(enums.Exchange.QUICK_1, response_payloads, 1,
                                          crypto=self.crypto, hashmsg=True)
        return self.sr_IKE(quick_mode_1_data, enums.message_name.quick_mode_1)

    def send_quick_mode_1_AH(self):
        self.esp_spi = os.urandom(4)
        values = self.AH_attr_values
        values[enums.ESPAttr.LIFE_TYPE] = 1  # second
        values[enums.ESPAttr.DURATION] = 3600
        values[enums.ESPAttr.LIFE_TYPE] = 2
        values[enums.ESPAttr.DURATION] = 28800
        my_AH_T_payload = message.Transform_1(1, self.AH_T_id, values)  # 这里与之前IKE不同
        my_AH_P_payload = message.Proposal_1(num=1, protocol=enums.Protocol.AH, spi=self.esp_spi,  # 这里写死了ESP
                                             transforms=[my_AH_T_payload])  # spi是空字符串
        src_ip_int = struct.unpack("!L", socket.inet_aton(self.my_IP))[0]
        dst_ip_int = struct.unpack("!L", socket.inet_aton(self.target_IP))[0]
        response_payloads = [message.PayloadSA_1(doi=1, situation=1, proposals=[my_AH_P_payload]),
                             message.PayloadNONCE_1(self.my_nonce),
                             message.PayloadID_1(id_type=1, id_data=struct.pack("!I", src_ip_int),
                                                 prot=enums.IpProto.ANY.value, port=0),
                             message.PayloadID_1(id_type=1, id_data=struct.pack("!I", dst_ip_int),
                                                 prot=enums.IpProto.ANY.value, port=0)]
        quick_mode_1_data, message_id = self.response(enums.Exchange.QUICK_1, response_payloads, 1,
                                          crypto=self.crypto, hashmsg=True)
        return self.sr_IKE(quick_mode_1_data, enums.message_name.quick_mode_1)

    def send_quick_mode_2(self):
        response_payloads = []
        if len(self.child_sa) == 0:
            quick_mode_2_data, message_id = self.response(enums.Exchange.QUICK_1, response_payloads, 1,
                                              crypto=self.crypto,
                                              hashmsg=os.urandom(64),
                                              quick_mode_3_flag=True)
        else:
            quick_mode_2_data, message_id = self.response(enums.Exchange.QUICK_1, response_payloads, 1,
                                              crypto=self.crypto,
                                              hashmsg=self.child_sa[-1].my_nonce + self.child_sa[-1].peer_nonce,
                                              quick_mode_3_flag=True)
        return self.sr_IKE(quick_mode_2_data, enums.message_name.quick_mode_2)

    def send_delete_ESP(self):
        if len(self.child_sa) == 0:
            delete_ESP_payload = message.PayloadDELETE_1(doi=1, protocol=enums.Protocol.ESP, spis=[os.urandom(4)])
        else:
            delete_ESP_payload = message.PayloadDELETE_1(doi=1, protocol=enums.Protocol.ESP,
                                                         spis=[self.child_sa[-1].spi_in])
        delete_ESP_data, message_id = self.response(enums.Exchange.INFORMATIONAL_1, [delete_ESP_payload], crypto=self.crypto,
                                        message_id=random.randint(1, math.pow(2, 23)-1), hashmsg=True)  
        return self.sr_IKE(delete_ESP_data, enums.message_name.delete_ESP)

    def send_delete_IKE(self):
        response_payloads = []
        response_payloads.append(
            message.PayloadDELETE_1(doi=1, protocol=enums.Protocol.IKE, spis=[self.my_spi + self.peer_spi]))
        delete_IKE_data, message_id = self.response(enums.Exchange.INFORMATIONAL_1, response_payloads, crypto=self.crypto,
                                        message_id=random.randint(1, math.pow(2, 23)-1), hashmsg=True)
        return self.sr_IKE(delete_IKE_data, enums.message_name.delete_IKE)

    def test_trans_ESP(self, new_flag=True):
        if len(self.child_sa) == 0:
            return enums.Response.Other
        if new_flag:
            child_sa = self.child_sa[-1]
        a = IP(dst=self.target_IP)
        a /= ICMP(type=8)
        if child_sa.crypto_out.cipher.transform not in list(default.crypt_algo_map.keys()) and \
                child_sa.crypto_out.integrity.transform not in list(default.auth_algo_map.keys()):
            print("UN_SUPPORT ESP ALGO")
            sys.exit()
        sa = SecurityAssociation(ESP, spi=struct.unpack('>L', bytes(child_sa.spi_out))[0],
                                 crypt_algo=default.crypt_algo_map[child_sa.crypto_out.cipher.transform],
                                 crypt_key=child_sa.crypto_out.sk_e,
                                 auth_algo=default.auth_algo_map[child_sa.crypto_out.integrity.transform],
                                 auth_key=child_sa.crypto_out.sk_a,
                                 )
        b = sa.encrypt(a, seq_num=child_sa.msgid_out)
        return self.sr_ipsec_ping(b, child_sa, proto=enums.Protocol.ESP)

    def test_tunnel_ESP(self, new_flag=True):
        if len(self.child_sa) == 0:
            return enums.Response.Other
        if new_flag:
            child_sa = self.child_sa[-1]
        a = IP(src=self.my_IP, dst=self.target_IP)
        a /= ICMP(type=8)
        if child_sa.crypto_out.cipher.transform not in list(default.crypt_algo_map.keys()) and \
                child_sa.crypto_out.integrity.transform not in list(default.auth_algo_map.keys()):
            print("UN_SUPPORT ESP ALGO")
            sys.exit()
        sa = SecurityAssociation(ESP, spi=struct.unpack('>L', bytes(child_sa.spi_out))[0],
                                 crypt_algo=default.crypt_algo_map[child_sa.crypto_out.cipher.transform],
                                 crypt_key=child_sa.crypto_out.sk_e,
                                 auth_algo=default.auth_algo_map[child_sa.crypto_out.integrity.transform],
                                 auth_key=child_sa.crypto_out.sk_a,
                                 tunnel_header=IP(src=self.my_IP, dst=self.target_IP)
                                 )
        b = sa.encrypt(a, seq_num=child_sa.msgid_out)
        return self.sr_ipsec_ping(b, child_sa, proto=enums.Protocol.ESP, tunnl=True)

    def test_trans_AH(self, new_flag=True):
        if len(self.child_sa) == 0:
            return enums.Response.Other
        if new_flag:
            child_sa = self.child_sa[-1]
        a = IP(dst=self.target_IP)
        a /= ICMP(type=8)
        if child_sa.crypto_out.integrity.transform not in list(default.auth_algo_map.keys()):
            print("UN_SUPPORT AH ALGO")
            sys.exit()
        sa = SecurityAssociation(AH, spi=struct.unpack('>L', bytes(child_sa.spi_out))[0],
                                 auth_algo=default.auth_algo_map[child_sa.crypto_out.integrity.transform],
                                 auth_key=child_sa.crypto_out.sk_a,
                                 )
        b = sa.encrypt(a, seq_num=child_sa.msgid_out)
        try:
            receive = self.sr_ipsec_ping(b, child_sa, proto=enums.Protocol.AH)
        except:
            print("Un_Known_Exception!")
            print(traceback.print_exc())
            return
        return receive

    def send_new_group(self):
        values = copy.deepcopy(self.IKE_attr_values)
        values[enums.TransformAttr.LIFETYPE] = 1  
        values[enums.TransformAttr.DURATION] = 28800
        my_IKE_T_payload = message.Transform_1(1, enums.Protocol.IKE,
                                               values)  
        my_IKE_P_payload = message.Proposal_1(num=1, protocol=enums.Protocol.IKE, spi=b'',
                                              transforms=[my_IKE_T_payload]) 
        response_payloads = [message.PayloadSA_1(doi=1, situation=1, proposals=[my_IKE_P_payload])]
        new_group_data, message_id = self.response(enums.Exchange.NEW_GROUP_1, response_payloads, crypto=self.crypto,
                                       hashmsg=True)
        return self.sr_IKE(new_group_data, enums.message_name.fuzz_mode)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__description__, epilog=f'Online help: <{__url__}>')
    parser.add_argument('-t', dest='target_IP', default='192.168.0.163', help='target_IP (default: 192.168.0.134)')
    parser.add_argument('-p', dest='passwd', default='123456', help='password (default: pipilu)')
    parser.add_argument('-i', dest='iface', default="ens37", help='iface (default: None)')
    parser.add_argument('-p12_cert', dest='p12_cert', default=None, help='p12_cert (default: ./client.cert.p12)')
    parser.add_argument('-client_private_key_file', dest='client_private_key_file', default=None, help='client_private_key_file (default: ./client.pem)')
    parser.add_argument('-public_cert', dest='public_cert', default=None, help='public_cert (default: ./client.cer)')
    parser.add_argument('--version', action='version', version=f'{__title__} {__version__}')
    args = parser.parse_args()
    args.DIRECT = pproxy.Connection('direct://')
    sessions = {}
    for i in range(1):
        my_IKEv1 = IKEv1_client(target_IP=args.target_IP, sessions=sessions, iface=args.iface,
                         my_IP="192.168.0.1", passwd=args.passwd, p12_cert=args.p12_cert,
                         public_cert=args.public_cert, client_private_key_file=args.client_private_key_file)
        # my_IKEv1.target_MAC = "00:0c:29:10:da:2f"
        # my_IKEv1.my_MAC = "00:50:56:c0:00:08"

        print(my_IKEv1.send_main_mode_1())
        print(my_IKEv1.send_main_mode_2())
        print(my_IKEv1.send_main_mode_3())
        print(my_IKEv1.send_quick_mode_1())
        print(my_IKEv1.send_quick_mode_2())
        print(my_IKEv1.test_tunnel_ESP())
        print(my_IKEv1.send_delete_ESP())
        print(my_IKEv1.send_delete_IKE())

