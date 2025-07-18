import argparse, os, sys, traceback, time, re, socket
import pproxy
from scapy.all import *
from scapy.layers.ipsec import *
from scapy.contrib.ikev2 import *
from pesp4 import enums, message
from pesp4.__doc__ import *
from pesp4.IKEfuzzer.IKE_fuzzer import *
from pesp4.IKEv2.IKEv2SecurityAssociation import *
from pesp4.IKEv2.Exception import *
from utils import *

global_ipsec_config = None
class MyThread(threading.Thread):
    def __init__(self, func, kwargs):
        super(MyThread, self).__init__()
        self.func = func
        self.kwargs = kwargs

    def run(self):
        self.result = self.func(**self.kwargs)

    def get_result(self):
        threading.Thread.join(self)
        try:
            return self.result
        except Exception:
            return None

class IKEv2_Client():
    def __init__(self, my_IP, target_IP, iface, passwd, ipsec_protocol=enums.Protocol.ESP, timeout=0.5, auth_mode=enums.AuthMethod.PSK, cert_file=None, cert_passwd=None, ipsec_config = None):
        self.my_MAC = None
        self.target_MAC = None
        self.NAT_flag = False
        self.local_IP = my_IP
        self.remote_IP = target_IP
        self.iface = iface
        self.ipsec_protocol = ipsec_protocol
        self.ipsec_config = ipsec_config
        self.timeout = timeout
        self.auth_mode = auth_mode
        self.cert_file = cert_file
        self.cert_passwd = cert_passwd
        
        global global_ipsec_config
        global_ipsec_config = ipsec_config


        # self.IKE_SA = None
        # To simplify the state machine, only one IKE SA is initialized 
        # at the beginning and no new IKE SA is created after that.
        self.IKE_SA = IKEv2SA(self.local_IP, self.remote_IP, auth_mode=self.auth_mode, psk=passwd,ipsec_config = self.ipsec_config, p12cert_file=self.cert_file, cert_passwd=self.cert_passwd)
        self.old_IKE_SA = None
        self.haveRekeyed = False
        
        self.current_abstractinput = None
        self.receive_IKE_message_list = []
        self.packets_buffer = []
        
        self.fuzz_plain_bytes = b''
        self.current_fuzz_plain = b''
        self.fuzzing = False
        self.fuzz_replay_mode = False
        self.fuzzer = IKE_fuzzer(version='v2')
        
    def my_srp1(self, pks, filter, verbose=0):
        try:
            timeout=self.timeout
            iface = self.iface
            # filter = "src host %s and " % self.remote_IP + filter if filter != "" else "src host %s" % self.remote_IP
            filter = f"src host {self.remote_IP} and dst host {self.local_IP}"
            # when send and receive IKE, we also sniff ICMP message
            if 'esp' not in filter:  
                filter = f'({filter}) or (src host {self.remote_IP} and icmp)'
            task = MyThread(sniff, {"iface": iface, "filter": filter, "timeout": timeout + 1 * 0.5})
            task.start()
            time.sleep(0.2)
            
            # fragment for winserver cert
            fragments = fragment(pks, 1400)
            for frag in fragments:
                send(frag[IP], iface=iface, verbose=verbose)
                self.packets_buffer.append(frag)
            pck = task.get_result()
            for p in pck:
                if 'UDP' in p:
                    pck = reassemble_udp_packets(pck)
                    break

            # time.sleep(0.1)
            # sendp(pks, iface=iface, verbose=verbose)
            # pck = task.get_result()
            self.packets_buffer.append(pks)
            self.packets_buffer.append(pck)
            if len(pck) != 0:
                return pck
            return None
        except:
            print("Exception in thread. Please restart mapper!")
            print(traceback.print_exc())
            sys.exit(-2)
        
    def sr_ispec_ping(self, abstractInput):
        if 'OI' in abstractInput:
            IKE = self.old_IKE_SA
        else:
            IKE = self.IKE_SA
        if IKE is None:
            return enums.Response.No_IKE_SA
        
        try:
            send_sa, send_message = IKE.instantiate_ipsec_message(abstractInput)
        except UnSupportedException:
            return enums.Response.Un_supported
        except NoChildSAException:
            return enums.Response.No_child_SA
        
        filter = "esp" if send_sa.protocol == enums.Protocol.ESP else "ah"
        received_message = self.my_srp1(send_message, filter=filter)
        return IKE.process_ipsec_response(send_sa, received_message)
        
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
    
    def sendAndRecv(self, abstractInput):
        result = None
        self.current_abstractinput = abstractInput
        if 'ipsec' in self.current_abstractinput:
            self.fuzz_plain_bytes += struct.pack('>H', 0)
            return self.sr_ispec_ping(self.current_abstractinput)
        else:
            if self.fuzzing:
                if random.randint(0, 3) == 0:
                    if 'RekeyIKE' in self.current_abstractinput:
                        prob_list = [('repeat', 0.1), ('remove', 0.1)]
                    else:
                        prob_list = [('repeat', 0.1), ('remove', 0.1), ('insert', 0.1)]
                    if 'OI_' in self.current_abstractinput:
                        self.current_abstractinput = self.current_abstractinput.split('OI_')[1]
                        self.current_abstractinput = fuzz_one_abstract_symbol(self.current_abstractinput, prob_list)
                        self.current_abstractinput = f'OI_{self.current_abstractinput}'  
                    else:
                        self.current_abstractinput = fuzz_one_abstract_symbol(self.current_abstractinput, prob_list)  
                    self.fuzzing = False
                    print(self.current_abstractinput)
            try:
                data = self.instantiate_IKE_message(self.current_abstractinput)
            except NoChildSAException:
                result = enums.Response.No_child_SA
            except NoIKESAException:
                result = enums.Response.No_IKE_SA
            except HaveRekeyedException:
                result = enums.Response.Have_Rekeyed
            except UnSupportedException:
                result = enums.Response.Un_supported
        
        if result is not None: # have not instantiate IKE message
            self.fuzz_plain_bytes += struct.pack('>H', 0)
        else:
            if not self.NAT_flag:
                if self.target_MAC is None or self.my_MAC is None:
                    send_message = Ether() / IP(src=self.local_IP, dst=self.remote_IP) / UDP(sport=500, dport=500) / raw(data)
                else:
                    send_message = Ether(src=self.my_MAC, dst=self.target_MAC) / IP(src=self.local_IP, dst=self.remote_IP) / UDP(sport=500, dport=500) / raw(data)
                received_message = self.my_srp1(send_message, filter="udp and port 500")
            else:
                send_message = Ether() / IP(dst=self.remote_IP) / UDP(sport=4500, dport=4500) / Raw(b'\x00' * 4 + data)
                received_message = self.my_srp1(send_message, filter="udp and port 4500")
            if received_message is None:
                result = enums.Response.No_response
            else:
                result = self.process_all(received_message)
        
        if result not in [enums.Response.No_IKE_SA, enums.Response.No_child_SA, enums.Response.Have_Rekeyed]: # new IKE_SA has been initialized
            # if rekey IKE failed, pop IKE_SA
            if 'RekeyIKE' in self.current_abstractinput and not self.haveRekeyed:
                self.IKE_SA = self.old_IKE_SA
                self.old_IKE_SA = None
        IKE = self.old_IKE_SA if 'OI' in self.current_abstractinput else self.IKE_SA
        if IKE is not None and IKE.Child_SA is not None:
            if not IKE.Child_SA.isNegotiatedCompleted:
                IKE.Child_SA = IKE.popLastOldChildSA()
                IKE.Child_SA_count -= 1
        return result
      
    # process currently received all messages
    def process_all(self, received_message):
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
                process_IKE_packs.append(UDPdata.payload)
            elif UDPdata.sport == 4500 and UDPdata.payload[:4] == b'\x00' * 4:
                payload = UDPdata.payload[4:]
                process_IKE_packs.append(payload)
        if len(process_IKE_packs) != 0:
            results = ''
            for IKE_pack in process_IKE_packs:

                result = self.process_one_IKE_message(IKE_pack)

                if result is not None:
                    results += (str(result) + '-')
            if len(results) >= 1:
                return results.strip('-')
        else:
            return enums.Response.No_response
        return enums.Response.No_response
    
    def instantiate_RekeyIKE_message(self, abstractInput):
        # TODO
        global global_ipsec_config
        ipsec_config = global_ipsec_config

        if self.IKE_SA is None:
            raise NoIKESAException
        elif self.IKE_SA.init_finshed is False:
            raise NoIKESAException
        if self.haveRekeyed:
            raise HaveRekeyedException
        self.old_IKE_SA = self.IKE_SA
        self.IKE_SA = IKEv2SA(self.local_IP, self.remote_IP, auth_mode=self.auth_mode, ipsec_config=ipsec_config, p12cert_file=self.cert_file, cert_passwd=self.cert_passwd)
        self.IKE_SA.isRekey = True
        msg = message.Message(self.old_IKE_SA.iCookie, self.old_IKE_SA.rCookie, 0x20, enums.Exchange.CREATE_CHILD_SA,
                              enums.MsgFlag.Initiator, self.old_IKE_SA.nextMessageID)
        tokens = re.split(r'[_-]', abstractInput)
        msg.exchange = enums.exchangeMap[tokens.pop(0)]
        for token in tokens:
            token = token.replace('*', '')
            if token == 'RekeyIKE':
                msg.payloads.append(self.old_IKE_SA.ciphersuite.getPayloadSA(spi=self.IKE_SA.iCookie))
            elif token == 'KE':
                msg.payloads.append(self.IKE_SA.generate_p1_KE_payload())
            elif token == 'NONCE':
                msg.payloads.append(self.IKE_SA.generate_p1_Nonce_payload())
            else:
                raise UnSupportedException

        if self.fuzz_replay_mode:
            # print(Fore.GREEN + str(self.fuzz_replay_data))
            self.fuzzer.fuzz_one_message_in_specific_location(msg, self.current_abstractinput)
            # print(Fore.GREEN + str(msg.to_bytes()))
            
        if self.fuzzing:
            self.current_abstractinput = self.fuzzer.fuzz_one_message(msg, self.current_abstractinput)
        self.current_fuzz_plain = msg.to_bytes(crypto=None)
        self.fuzz_plain_bytes += struct.pack('>H', len(self.current_fuzz_plain))
        self.fuzz_plain_bytes += self.current_fuzz_plain
            
        c = self.old_IKE_SA.getICrypto()
        data = msg.to_bytes(crypto=c)
        return data
    
    def process_RekeyIKE_response(self, IKE_data):
        stream = io.BytesIO(bytes(IKE_data))
        response = message.Message.parse(stream)
        if response.spi_i != self.old_IKE_SA.iCookie:
            return None
        self.old_IKE_SA.nextMessageID += 1
        try:
            response.parse_payloads(stream, crypto=self.old_IKE_SA.getRCrypto())
        except:
            return enums.Response.DecryptedError
        spiReceived = False
        abstractOutput = ''
        if response.first_payload != enums.Payload.SK and response.exchange != enums.Exchange.IKE_SA_INIT:
            abstractOutput += '!'
        for key, value in enums.exchangeMap.items():
            if value == response.exchange:
                abstractOutput += (key + '_')
        for pd in response.payloads:
            abbr = (str(pd.type).split('Payload.')[1] + '-')
            if pd.type == enums.Payload.SA:
                self.IKE_SA.ciphersuite.adjustPayloadSA(pd)
                if len(pd.proposals[0].spi) == 8:
                    self.IKE_SA.rCookie = pd.proposals[0].spi
                    spiReceived = True
                    abbr = 'RekeyIKE-'
            elif pd.type == enums.Payload.KE:
                self.IKE_SA.peerdhPublicKey = pd.ke_data
                self.IKE_SA.computeDHSecret()
            elif pd.type == enums.Payload.NONCE:
                self.IKE_SA.responderNonce = pd.nonce
            elif pd.type == enums.Payload.NOTIFY:
                abbr = hex(pd.notify).split('0x')[1] + '-'
            abstractOutput += abbr        
        abstractOutput = abstractOutput.strip('-')
        # if rekey successed, hand over all child SA
        if spiReceived and ('KE' in abstractOutput) and ('NONCE' in abstractOutput):
            self.IKE_SA.Child_SA = self.old_IKE_SA.Child_SA
            self.IKE_SA.old_Child_SA = self.old_IKE_SA.old_Child_SA
            self.IKE_SA.Child_SA_count = self.old_IKE_SA.Child_SA_count
            self.IKE_SA.old_ciphersuite = self.old_IKE_SA.ciphersuite
            self.IKE_SA.old_SK_d = self.old_IKE_SA.KEYs.SK_d
            self.IKE_SA.init_finshed = True
            self.old_IKE_SA.Child_SA = None
            self.old_IKE_SA.old_Child_SA = OrderedDict()
            self.old_IKE_SA.Child_SA_count = 0
            self.haveRekeyed = True
        return abstractOutput
     
    def instantiate_IKE_message(self, abstractInput):
        if 'RekeyIKE' in abstractInput:
            return self.instantiate_RekeyIKE_message(abstractInput)
        if 'OI' in abstractInput:
            if self.old_IKE_SA is None:
                raise NoIKESAException
            IKE = self.old_IKE_SA
            abstractInput = abstractInput.split('OI_')[1]
        else:
            if self.IKE_SA is None:
                raise NoIKESAException
            IKE = self.IKE_SA
        tokens = re.split(r'[_-]', abstractInput)
        msg = message.Message(IKE.iCookie, IKE.rCookie, 0x20, enums.Exchange.IKE_SA_INIT,
                              enums.MsgFlag.Initiator, IKE.nextMessageID)
        # msg = message.Message(n1.to_bytes(8, 'big'), n2.to_bytes(8, 'big'), 0x20, enums.Exchange.IKE_SA_INIT,
        #                       enums.MsgFlag.Initiator, 0x02)
        msg.exchange = enums.exchangeMap[tokens.pop(0)]
        IKE.computeSecretKeys()
        for token in tokens:
            token = token.replace('*', '')
            if token == 'SA':
                if msg.exchange == enums.Exchange.IKE_SA_INIT:
                    msg.payloads.append(IKE.generate_p1_SA_payload())
                else:
                    msg.payloads.append(IKE.generate_p2_SA_payload(self.ipsec_protocol, self.remote_IP))
            elif token == 'KE':
                if msg.exchange == enums.Exchange.IKE_SA_INIT:
                    msg.payloads.append(IKE.generate_p1_KE_payload())
                else:
                    msg.payloads.append(IKE.generate_p2_KE_payload(self.ipsec_protocol, self.remote_IP))
            elif token == 'NONCE':
                if msg.exchange == enums.Exchange.IKE_SA_INIT:
                    msg.payloads.append(IKE.generate_p1_Nonce_payload())
                else:
                    msg.payloads.append(IKE.generate_p2_Nonce_payload(self.ipsec_protocol, self.remote_IP))
            elif token == 'IDi':
                if IKE.auth_mode == enums.AuthMethod.PSK:
                    pd = IKE.generate_IDi_payload(enums.IDType.ID_IPV4_ADDR, socket.inet_aton(IKE.local_IP))
                else:
                    pd = IKE.generate_IDi_payload(enums.IDType.ID_FQDN, IKE.id.encode('utf-8'))
                msg.payloads.append(pd)
                IKE.IDi = pd.to_bytes()
            elif token == 'AUTH':
                msg.payloads.append(IKE.generate_AUTH_payload())
            elif token == 'TSi':
                msg.payloads.append(IKE.generate_TSi_payload())
            elif token == 'TSr':
                msg.payloads.append(IKE.generate_TSr_payload())
            elif token == 'DelChild':
                if IKE.Child_SA is None:
                    raise NoChildSAException
                msg.payloads.append(IKE.generate_Del_Child_payload())
            elif token == 'DelOldChild':
                if len(IKE.old_Child_SA) == 0:
                    raise NoChildSAException
                msg.payloads.append(IKE.generate_Del_Old_Child_payload())
            elif token == 'DelIKE':
                msg.payloads.append(IKE.generate_Del_IKE_payload())
            elif token == 'RekeySA':
                if IKE.Child_SA is None:
                    raise NoChildSAException
                msg.payloads.append(IKE.generate_RekeySA_payload(self.ipsec_protocol))
            elif token == 'TransMode':
                if IKE.Child_SA is None:
                    IKE.Child_SA = ChildSA(protocol=self.ipsec_protocol, local_ip=self.local_IP, remote_ip=self.remote_IP)
                elif IKE.Child_SA.isNegotiatedCompleted:
                    IKE.old_Child_SA[IKE.Child_SA_count] = IKE.Child_SA
                    IKE.Child_SA = ChildSA(protocol=self.ipsec_protocol, local_ip=self.local_IP, remote_ip=self.remote_IP)
                    IKE.Child_SA_count += 1
                msg.payloads.append(IKE.generate_Notify_payload(notify_type=enums.Notify.USE_TRANSPORT_MODE))
            elif token == 'CERT':
                msg.payloads.append(IKE.generate_CERT_payload())
            elif token == 'CERTREQ':
                msg.payloads.append(IKE.generate_CERTREQ_payload())
            elif token == 'AuthTime':
                msg.payloads.append(IKE.generate_Notify_payload(notify_type=enums.Notify.AUTH_LIFETIME, data=os.urandom(random.randint(0, 32))))
            elif token == 'fragment':
                msg.payloads.append(IKE.generate_Notify_payload(notify_type=enums.Notify.IKEV2_FRAGMENTATION_SUPPORTED))
            elif token == 'mobike':
                msg.payloads.append(IKE.generate_Notify_payload(notify_type=enums.Notify.MOBIKE_SUPPORTED))
            elif token == 'Conf':
                msg.payloads.append(IKE.generate_Conf_payload())
            elif token == '':
                continue
            else:
                raise UnSupportedException
    
        if self.fuzz_replay_mode:
            self.fuzzer.fuzz_one_message_in_specific_location(msg, self.current_abstractinput)

        if self.fuzzing:
            abstractInput = self.fuzzer.fuzz_one_message(msg, abstractInput)
            if 'OI_' in self.current_abstractinput:
                self.current_abstractinput = f'OI_{abstractInput}'
            else:
                self.current_abstractinput = abstractInput
        self.current_fuzz_plain = msg.to_bytes(crypto=None)
        self.fuzz_plain_bytes += struct.pack('>H', len(self.current_fuzz_plain))
        self.fuzz_plain_bytes += self.current_fuzz_plain

        if msg.exchange == enums.Exchange.IKE_SA_INIT:
            data = msg.to_bytes()
            IKE.RealMessage = data
        # elif msg.exchange == enums.Exchange.CREATE_CHILD_SA:
        #     IKE.initiatorNonce = os.urandom(32)
        #     IKE.computeSecretKeys()
        #     c = IKE.getICrypto()
        #     data = msg.to_bytes(crypto=c)
            # data = data[:-10]
        else:
            c = IKE.getICrypto()
            data = msg.to_bytes(crypto=c)
        
        return data
    
    def process_one_IKE_message(self, IKE_data):
        for receive_message in self.receive_IKE_message_list:
            if IKE_data == receive_message:
                return None
        self.receive_IKE_message_list.append(IKE_data)
        if 'RekeyIKE' in self.current_abstractinput:
            return self.process_RekeyIKE_response(IKE_data)
        if 'OI' in self.current_abstractinput:
            IKE = self.old_IKE_SA
        else:
            IKE = self.IKE_SA
        stream = io.BytesIO(bytes(IKE_data))
        response = message.Message.parse(stream)
        if response.flag == enums.MsgFlag.NONE:
            return None
        if response.spi_i != IKE.iCookie:
            return None
        IKE.nextMessageID += 1
        try:
            response.parse_payloads(stream, crypto=IKE.getRCrypto())
        except:
            return enums.Response.DecryptedError
        
        IKE.rCookie = response.spi_r
        abstractOutput = ''
        if response.first_payload != enums.Payload.SK and response.exchange != enums.Exchange.IKE_SA_INIT:
            abstractOutput += '!'
            
        for key, value in enums.exchangeMap.items():
            if value == response.exchange:
                abstractOutput += (key + '_')
        for pd in response.payloads:
            abbr = (str(pd.type).split('Payload.')[1] + '-')
            
            if pd.type == enums.Payload.SA:
                if response.exchange == enums.Exchange.IKE_SA_INIT:
                    IKE.ciphersuite.adjustPayloadSA(pd)
                    IKE.init_finshed = True
                else:
                    if IKE.Child_SA:
                        IKE.Child_SA.ciphersuite.adjustPayloadSA(pd)
                        proposal = pd.proposals[0]
                        IKE.Child_SA.SPIi = proposal.spi
            elif pd.type == enums.Payload.KE:
                if response.exchange == enums.Exchange.IKE_SA_INIT:
                    IKE.peerdhPublicKey = pd.ke_data
                    IKE.computeDHSecret()
                else:
                    if IKE.Child_SA:
                        IKE.Child_SA.peerdhPublicKey = pd.ke_data
                        IKE.Child_SA.computeDHSecret()
            elif pd.type == enums.Payload.NONCE:
                if response.exchange == enums.Exchange.IKE_SA_INIT:
                    IKE.responderNonce = pd.nonce
                else:
                    if IKE.Child_SA:
                        IKE.Child_SA.responderNonce = pd.nonce
            elif pd.type == enums.Payload.NOTIFY:
                # abbr = str(pd.notify).split('Notify.')[1] + '-'
                abbr = hex(pd.notify).split('0x')[1] + '-'
                if pd.notify == enums.Notify.USE_TRANSPORT_MODE:
                    abbr = 'TransMode-'
            elif pd.type == enums.Payload.DELETE:
                if len(pd.spis) > 0:
                    abbr = 'DelChild-'
                    for spi in pd.spis:
                        # print(spi.hex())
                        if spi == IKE.Child_SA.SPIi:
                            IKE.Child_SA = IKE.popLastOldChildSA()
                            IKE.Child_SA_count -= 1
                        elif len(IKE.old_Child_SA) > 0:
                            for k in IKE.old_Child_SA.keys():
                                if spi == IKE.old_Child_SA[k].SPIi:
                                    IKE.old_Child_SA.pop(k)
                                    IKE.Child_SA_count -= 1
                                    break
                    
            abstractOutput += abbr        
        abstractOutput = abstractOutput.strip('-')

        if response.exchange == enums.Exchange.IKE_AUTH or response.exchange == enums.Exchange.CREATE_CHILD_SA:
            try:
                if 'SA' in abstractOutput.split('_')[1]:
                    IKE.Child_SA.computeKeyMaterial(IKE.ciphersuite.attrs[enums.Transform.PRF][0], IKE.KEYs.SK_d, 
                                                            IKE.initiatorNonce + IKE.responderNonce)
                    IKE.Child_SA.isNegotiatedCompleted = True
            except:
                return enums.Response.No_response
            
        if response.exchange == enums.Exchange.INFORMATIONAL:
            if 'DelIKE' in self.current_abstractinput and len(response.payloads) == 0:
                # IKE = None
                if '!' not in abstractOutput:
                    abstractOutput = 'INFO_DelIKE'
                # if 'OI' in self.current_abstractinput:
                #     self.old_IKE_SA = None
                # else:
                #     self.IKE_SA = None
        
        if '!' in abstractOutput:
            abstractOutput = 'Plain_response'
        return abstractOutput




