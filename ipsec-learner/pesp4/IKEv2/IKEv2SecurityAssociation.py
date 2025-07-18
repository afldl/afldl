import os, io
from pesp4 import enums, message, crypto
from pesp4.__doc__ import *
from pesp4.IKEv2.Exception import *
from collections import OrderedDict
import ipaddress
from scapy.all import *
from scapy.layers.ipsec import *
from OpenSSL import crypto as sslcrypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import copy
import utils

global_ipsec_config = None

class Ciphersuite:
    def __init__(self, prot,ipsec_config):
        self.prot = prot


        self.ipsec_config = ipsec_config
        # print(ipsec_config)
        IKE_attrs,ESP_attrs,AH_attrs = utils.ipsec_config_v2(ipsec_config)

        if prot == enums.Protocol.IKE:
            
            # self.attrs = {
            #     enums.Transform.ENCR: (enums.EncrId.ENCR_AES_CBC, enums.KeyLength.AES_128),
            #     enums.Transform.PRF: (enums.PrfId.PRF_HMAC_SHA1, None),
            #     enums.Transform.INTEG: (enums.IntegId.AUTH_HMAC_SHA1_96, None),
            #     enums.Transform.DH: (enums.DhId.DH_5, None),
            #     enums.Transform.ESN: (None, None)
            # }
            # self.attrs = {
            #     enums.Transform.ENCR: (enums.EncrId.ENCR_3DES, None),
            #     enums.Transform.PRF: (enums.PrfId.PRF_HMAC_SHA1, None),
            #     enums.Transform.INTEG: (enums.IntegId.AUTH_HMAC_SHA1_96, None),
            #     enums.Transform.DH: (enums.DhId.DH_2, None),
            #     enums.Transform.ESN: (None, None)
            # }
            self.attrs = IKE_attrs
        elif prot == enums.Protocol.ESP:
            # self.attrs = {
            #     enums.Transform.ENCR: (enums.EncrId.ENCR_AES_CBC, enums.KeyLength.AES_128),
            #     enums.Transform.PRF: (None, None),
            #     enums.Transform.INTEG: (enums.IntegId.AUTH_HMAC_SHA1_96, None),
            #     enums.Transform.DH: (None, None),
            #     enums.Transform.ESN: (enums.EsnId.NO_ESN, None)
            # }
            # self.attrs = {
            #     enums.Transform.ENCR: (enums.EncrId.ENCR_3DES, None),
            #     enums.Transform.PRF: (None, None),
            #     enums.Transform.INTEG: (enums.IntegId.AUTH_HMAC_SHA1_96, None),
            #     enums.Transform.DH: (None, None),
            #     enums.Transform.ESN: (enums.EsnId.NO_ESN, None)
            # }
            self.attrs = ESP_attrs

        elif prot == enums.Protocol.AH:
            # self.attrs = {
            #     enums.Transform.ENCR: (None, None),
            #     enums.Transform.PRF: (None, None),
            #     enums.Transform.INTEG: (enums.IntegId.AUTH_HMAC_SHA1_96, None),
            #     enums.Transform.DH: (None, None),
            #     enums.Transform.ESN: (enums.EsnId.NO_ESN, None)
            # }
            self.attrs = AH_attrs


    def adjustPayloadSA(self, payload:message.PayloadSA):
        if len(payload.proposals) != 1:
            return 
        for key in self.attrs.keys():
            self.attrs[key] = (None, None)
        proposal = payload.proposals[0]
        trans = proposal.transforms
        for t in trans:
            self.attrs[t.type] = (t.id, t.keylen)
                
    def getPayloadSA(self, spi=b''):
        transforms = []
        for key, value in self.attrs.items():
            if value[0] is not None:
                transforms.append(message.Transform(key, value[0], value[1]))
        proposal = [message.Proposal(1, self.prot, spi, transforms)]
        return message.PayloadSA(proposal)

class IKE_key:
    def __init__(self):
        self.SKEYSEED = None
        self.SK_d = None
        self.SK_ai = None
        self.SK_ar = None
        self.SK_ei = None
        self.SK_er = None
        self.SK_pi = None
        self.SK_pr = None
        
    def compute_all(self, ciphersuite:Ciphersuite, Ni, Nr, SPIi, SPIr, dhkey, isRekey=False, old_ciphersuite:Ciphersuite=None, old_SK_d=None):
        if isRekey:
            prf = crypto.Prf(old_ciphersuite.attrs[enums.Transform.PRF][0])

            self.SKEYSEED = prf.prf(old_SK_d, dhkey+Ni+Nr)
        else:
            prf = crypto.Prf(ciphersuite.attrs[enums.Transform.PRF][0])
            self.SKEYSEED = prf.prf(Ni+Nr, dhkey)
        temp = bytes(prf.prfplus(self.SKEYSEED, Ni + Nr + SPIi + SPIr))
        stream = io.BytesIO(temp)
        cipher = crypto.Cipher(ciphersuite.attrs[enums.Transform.ENCR][0], ciphersuite.attrs[enums.Transform.ENCR][1])
        integ = crypto.Integrity(ciphersuite.attrs[enums.Transform.INTEG][0])
        self.SK_d = stream.read(prf.key_size)
        self.SK_ai = stream.read(integ.key_size)
        self.SK_ar = stream.read(integ.key_size)
        self.SK_ei = stream.read(cipher.key_size)
        self.SK_er = stream.read(cipher.key_size)
        self.SK_pi = stream.read(prf.key_size)
        self.SK_pr = stream.read(prf.key_size)
        # print('*'*100)
        # print(self.SKEYSEED.hex())
        # print(self.SK_d.hex())
        # print(self.SK_ai.hex())
        # print(self.SK_ar.hex())
        # print(self.SK_ei.hex())
        # print(self.SK_er.hex())
        # print(self.SK_pi.hex())
        # print(self.SK_pr.hex())


class GenericSA:
    def __init__(self, protocol = enums.Protocol.ESP,ipsec_config = None):
        self.ciphersuite = Ciphersuite(protocol,ipsec_config)
        self.DHGroup = self.ciphersuite.attrs[enums.Transform.DH][0]
        self.protocol = protocol
        self.dhPrivateKey = None
        self.dhPublicKey = None
        self.peerdhPublicKey = None
        self.dhSecret = None
        self.initiatorNonce = None
        self.responderNonce = None
        
    def generateDhKeyPair(self):
        self.dhPublicKey, self.dhPrivateKey = crypto.DH_create_my_public_key(self.DHGroup)
    def generatePeerDhKeyPair(self):
        self.peerdhPublicKey, _ = crypto.DH_create_my_public_key(self.DHGroup)
    def computeDHSecret(self):
        # print('self.dhPrivateKey: ' + str(self.dhPrivateKey))
        # print('self.peerdhPublicKey: ' + self.peerdhPublicKey.hex())
        if self.dhPrivateKey is None or self.peerdhPublicKey is None:
            self.generateDhKeyPair()
            self.generatePeerDhKeyPair()
        self.dhSecret = crypto.DH_caculate_shared_secret(self.DHGroup, self.dhPrivateKey, self.peerdhPublicKey)
        # print('self.dhSecret: ' + self.dhSecret.hex())
    def generateKeyExchangeData(self):
        if self.dhPublicKey is None:
            self.generateDhKeyPair()
        return self.dhPublicKey
    
class ChildSA(GenericSA):
    def __init__(self, protocol = enums.Protocol.ESP, local_ip=None, remote_ip=None, tunnel_ip=None,ipsec_config = None):
        GenericSA.__init__(self, protocol,ipsec_config)
        self.SPIi = bytes(4)
        self.SPIr = bytes(4)
        self.ei = None
        self.er = None
        self.ai = None
        self.ar = None
        self.msgid_in = 1
        self.msgid_out = 1
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.tunnel_ip = tunnel_ip
        self.isNegotiatedCompleted = False
        if self.DHGroup is None or self.DHGroup == enums.DhId.DH_NONE:
            self.DHGroup = enums.DhId.DH_5
    
    def getENCRid(self):
        return self.ciphersuite.attrs[enums.Transform.ENCR][0]
    
    def getINTEDid(self):
        return self.ciphersuite.attrs[enums.Transform.INTEG][0]
        
    def computeKeyMaterial(self, prfid, SK_d, IKEconcatNonces):
        prf = crypto.Prf(prfid)
        dhsecret = self.dhSecret if self.dhSecret is not None else bytes(0)
        if self.initiatorNonce is None or self.responderNonce is None:
            concatNonces = IKEconcatNonces
        else:
            concatNonces = self.initiatorNonce + self.responderNonce
        # print('dhsecret: ' + dhsecret.hex())
        # print('concatNonces: ' + concatNonces.hex())
        KEYMAT = bytes(prf.prfplus(SK_d, dhsecret + concatNonces))
        stream = io.BytesIO(KEYMAT)
        if self.protocol == enums.Protocol.ESP:
            cipher = crypto.Cipher(self.ciphersuite.attrs[enums.Transform.ENCR][0], self.ciphersuite.attrs[enums.Transform.ENCR][1])
        integ = crypto.Integrity(self.ciphersuite.attrs[enums.Transform.INTEG][0])
        if self.protocol == enums.Protocol.ESP:
            self.ei = stream.read(cipher.key_size)
        self.ai = stream.read(integ.key_size)
        if self.protocol == enums.Protocol.ESP:
            self.er = stream.read(cipher.key_size)
        self.ar = stream.read(integ.key_size)
        # print('self.ei: ' + self.ei.hex())
        # print('self.ai: ' + self.ai.hex())
        # print('self.er: ' + self.er.hex())
        # print('self.ar: ' + self.ar.hex())

class IKEv2SA(GenericSA):
    def __init__(self, local_IP, remote_IP, protocol=enums.Protocol.IKE, auth_mode=enums.AuthMethod.RSA,
                 psk='123456', p12cert_file=None, cert_passwd=None,ipsec_config = None):
        
        # TODO


        GenericSA.__init__(self, protocol,ipsec_config)

        self.ipsec_config = ipsec_config
        self.generateDhKeyPair()
        self.generatePeerDhKeyPair()
        self.computeDHSecret()
        self.initiatorNonce = os.urandom(32)
        self.responderNonce = bytes(32)
        self.init_finshed = False
        
        self.iCookie = os.urandom(8)
        self.rCookie = bytes(8)
        self.auth_mode = auth_mode
        self.psk = psk
        self.cert_passwd = cert_passwd
        self.load_key_and_cert(p12cert_file)
        self.KEYs = IKE_key()
        self.IDi = bytes(0)
        self.IDr = bytes(0)
        self.octets = bytes(0)
        self.RealMessage = bytes(0)
        self.nextMessageID = 0
        self.local_IP = local_IP
        self.remote_IP = remote_IP
        
        self.old_Child_SA = OrderedDict()
        self.Child_SA_count = 0
        self.Child_SA = None
        
        self.isRekey = False
        self.old_SK_d = None
        self.old_ciphersuite = None
        
    def computeSecretKeys(self):
        # print('self.iCookie: ' + self.iCookie.hex())
        # print('self.rCookie: ' + self.rCookie.hex())
        # print('self.initiatorNonce: ' + self.initiatorNonce.hex())
        # print('self.responderNonce: ' + self.responderNonce.hex())
        self.KEYs.compute_all(self.ciphersuite, self.initiatorNonce, self.responderNonce,
                                    self.iCookie, self.rCookie, self.dhSecret, 
                                    self.isRekey, self.old_ciphersuite, self.old_SK_d)
    
    def load_key_and_cert(self, p12_file):
        if p12_file is None:
            return 
        with open(p12_file, 'rb') as f:
            p12_data = f.read()
        p12 = sslcrypto.load_pkcs12(p12_data, self.cert_passwd.encode('utf-8'))
        self.rsakey = load_pem_private_key(
            sslcrypto.dump_privatekey(sslcrypto.FILETYPE_PEM, p12.get_privatekey()),
            password=None,
            backend=default_backend()
        )
        self.cert = load_pem_x509_certificate(
            sslcrypto.dump_certificate(sslcrypto.FILETYPE_PEM, p12.get_certificate()),
            backend=default_backend()
        )
        self.id = self.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            
    def computeOctets(self):
        prf = crypto.Prf(self.ciphersuite.attrs[enums.Transform.PRF][0])
        # print('self.KEYs.SK_pi: ' + self.KEYs.SK_pi.hex())
        # print('self.IDi: ' + self.IDi.hex())
        MACedIDForI = prf.prf(self.KEYs.SK_pi, self.IDi)
        self.octets += self.RealMessage
        self.octets += self.responderNonce
        self.octets += MACedIDForI
        # print('self.RealMessage: ' + self.RealMessage.hex())
        # print('self.responderNonce: ' + self.responderNonce.hex())
        # print('self.MACedIDForI: ' + MACedIDForI.hex())
    
    def computeAUTH(self):
        self.computeOctets()
        if self.auth_mode == enums.AuthMethod.PSK:
            prf = crypto.Prf(self.ciphersuite.attrs[enums.Transform.PRF][0])
            innerprf = prf.prf(self.psk.encode(), "Key Pad for IKEv2".encode())
            result = prf.prf(innerprf, self.octets)
        elif self.auth_mode == enums.AuthMethod.RSA:
            #TODO
            result = self.rsakey.sign(
                self.octets,
                padding.PKCS1v15(),
                hashes.SHA1()
            )
        else:
            result = None
        return result
    
    def getICrypto(self):
        cipher = crypto.Cipher(self.ciphersuite.attrs[enums.Transform.ENCR][0], self.ciphersuite.attrs[enums.Transform.ENCR][1])
        integ = crypto.Integrity(self.ciphersuite.attrs[enums.Transform.INTEG][0])
        prf = crypto.Prf(self.ciphersuite.attrs[enums.Transform.PRF][0])
        c = crypto.Crypto(cipher, self.KEYs.SK_ei, integ, self.KEYs.SK_ai, prf, self.KEYs.SK_pi)
        return c
    
    def getRCrypto(self):
        cipher = crypto.Cipher(self.ciphersuite.attrs[enums.Transform.ENCR][0], self.ciphersuite.attrs[enums.Transform.ENCR][1])
        integ = crypto.Integrity(self.ciphersuite.attrs[enums.Transform.INTEG][0])
        prf = crypto.Prf(self.ciphersuite.attrs[enums.Transform.PRF][0])
        c = crypto.Crypto(cipher, self.KEYs.SK_er, integ, self.KEYs.SK_ar, prf, self.KEYs.SK_pr)
        return c
    
    def getLastOldChildSA(self):
        if len(self.old_Child_SA) == 0:
            return None
        return list(self.old_Child_SA.values())[-1]
    
    def popLastOldChildSA(self):
        if len(self.old_Child_SA) == 0:
            return None
        last_key = list(self.old_Child_SA.keys())[-1]
        return self.old_Child_SA.pop(last_key)
        
    #------------------------------------------------------------
    # The functions to generate one specific type IKEv2 payload
    #------------------------------------------------------------   
    def generate_p1_SA_payload(self):
        return self.ciphersuite.getPayloadSA()
    
    def generate_p2_SA_payload(self, ipsec_protocol, remote_IP):
        if self.Child_SA is None:
            self.Child_SA = ChildSA(protocol=ipsec_protocol, local_ip=self.local_IP, remote_ip=self.remote_IP, tunnel_ip=remote_IP,ipsec_config=self.ipsec_config)
            self.Child_SA_count += 1
        elif self.Child_SA.isNegotiatedCompleted:
            self.old_Child_SA[self.Child_SA_count] = self.Child_SA
            self.Child_SA = ChildSA(protocol=ipsec_protocol, local_ip=self.local_IP, remote_ip=self.remote_IP, tunnel_ip=remote_IP,ipsec_config=self.ipsec_config)
            self.Child_SA_count += 1
        if self.Child_SA.SPIr == bytes(4):
            self.Child_SA.SPIr = os.urandom(4)
        return self.Child_SA.ciphersuite.getPayloadSA(self.Child_SA.SPIr)

    def generate_p1_KE_payload(self):
        data = self.generateKeyExchangeData()
        return message.PayloadKE(self.DHGroup, data)
    
    def generate_p2_KE_payload(self, ipsec_protocol, remote_IP):
        if self.Child_SA is None:
            self.Child_SA = ChildSA(protocol=ipsec_protocol, local_ip=self.local_IP, remote_ip=self.remote_IP, tunnel_ip=remote_IP,ipsec_config=self.ipsec_config)
        elif self.Child_SA.isNegotiatedCompleted:
            self.old_Child_SA[self.Child_SA_count] = self.Child_SA
            self.Child_SA = ChildSA(protocol=ipsec_protocol, local_ip=self.local_IP, remote_ip=self.remote_IP, tunnel_ip=remote_IP,ipsec_config=self.ipsec_config)
            self.Child_SA_count += 1
        return message.PayloadKE(self.Child_SA.DHGroup, self.Child_SA.generateKeyExchangeData())
    
    def generate_p1_Nonce_payload(self):
        Nonce = message.PayloadNONCE(self.initiatorNonce)
        return Nonce
    
    def generate_p2_Nonce_payload(self, ipsec_protocol, remote_IP):
        if self.Child_SA is None:
            self.Child_SA = ChildSA(protocol=ipsec_protocol, local_ip=self.local_IP, remote_ip=self.remote_IP, tunnel_ip=remote_IP,ipsec_config=self.ipsec_config)
        elif self.Child_SA.isNegotiatedCompleted:
            self.old_Child_SA[self.Child_SA_count] = self.Child_SA
            self.Child_SA = ChildSA(protocol=ipsec_protocol, local_ip=self.local_IP, remote_ip=self.remote_IP, tunnel_ip=remote_IP,ipsec_config=self.ipsec_config)
            self.Child_SA_count += 1
        if self.Child_SA.initiatorNonce is None:
            self.Child_SA.initiatorNonce = os.urandom(32)
        Nonce = message.PayloadNONCE(self.Child_SA.initiatorNonce)
        return Nonce
    
    def generate_IDi_payload(self, id_type=enums.IDType.ID_IPV4_ADDR, id_data=b''):
        IDi = message.PayloadIDi(id_type, id_data)
        return IDi
    
    def generate_IDr_payload(self, id_type=enums.IDType.ID_IPV4_ADDR, id_data=b''):
        IDi = message.PayloadIDr(id_type, id_data)
        return IDi
        
    def generate_CERT_payload(self):
        cert = message.PayloadCERT(enums.CertCode.X509CertificateSignature, self.cert.public_bytes(serialization.Encoding.DER))
        return cert
    
    def generate_CERTREQ_payload(self):
        data = bytes.fromhex('92faf752a6a4c0359d974cf5b394d15fc135f5a8')
        certreq = message.PayloadCERTREQ(enums.CertCode.X509CertificateSignature, data)
        return certreq
        
    def generate_AUTH_payload(self):
        auth_data = self.computeAUTH()
        AUTH = message.PayloadAUTH(self.auth_mode, auth_data)
        return AUTH
    
    def generate_TSi_payload(self):
        if 'site2site' in self.ipsec_config:
            ts = message.TrafficSelector(enums.TSType.TS_IPV4_ADDR_RANGE, enums.IpProto.ANY,
                                        0, 65535, ipaddress.ip_address('0.0.0.0'), ipaddress.ip_address('255.255.255.255')) # for winserver
        else:
            ts = message.TrafficSelector(enums.TSType.TS_IPV4_ADDR_RANGE, enums.IpProto.ANY,
                             0, 65535, ipaddress.ip_address(self.local_IP), ipaddress.ip_address(self.local_IP))
        TSi = message.PayloadTSi([ts])
        return TSi
    
    def generate_TSr_payload(self):
        if 'site2site' in self.ipsec_config:

            ts = message.TrafficSelector(enums.TSType.TS_IPV4_ADDR_RANGE, enums.IpProto.ANY,
                                        0, 65535, ipaddress.ip_address('0.0.0.0'), ipaddress.ip_address('255.255.255.255')) # for winserver
        else:
            ts = message.TrafficSelector(enums.TSType.TS_IPV4_ADDR_RANGE, enums.IpProto.ANY,
                             0, 65535, ipaddress.ip_address(self.remote_IP), ipaddress.ip_address(self.remote_IP))
        TSr = message.PayloadTSr([ts])
        return TSr
    
    def generate_Del_Child_payload(self):
        spis = [self.Child_SA.SPIr]
        DEL = message.PayloadDELETE(self.Child_SA.protocol, spis)
        return DEL
    
    def generate_Del_Old_Child_payload(self):
        spis = []
        for sa in self.old_Child_SA.values():
            spis.append(sa.SPIr)
        DEL = message.PayloadDELETE(self.Child_SA.protocol, spis)
        return DEL
    
    def generate_Del_IKE_payload(self):
        spis = []
        DEL = message.PayloadDELETE(self.protocol, spis)
        return DEL
        
    def generate_Notify_payload(self, protocol=enums.Protocol.NONE, notify_type=enums.Notify.UNSUPPORTED_CRITICAL_PAYLOAD, spi=b'', data=b''):
        Notify = message.PayloadNOTIFY(protocol, notify_type, spi, data)
        return Notify    
    
    def generate_Conf_payload(self):
        cp = message.PayloadCP(type=enums.CFGType.CFG_REQUEST, attrs=None)
        data = b"\x01\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x5b\xa0\x00\x00\x00\x08\x00\x00\x00\x0a\x00\x00\x5b\xa1\x00\x00"
        cp.parse_data(io.BytesIO(data), len(data))
        return cp   
    
    def generate_RekeySA_payload(self, ipsec_protocol):
        Notify = message.PayloadNOTIFY(ipsec_protocol, enums.Notify.REKEY_SA, self.Child_SA.SPIr, b'')
        return Notify   
    
    def instantiate_ipsec_message(self, abstractInput):
        if 'old' in abstractInput:
            child_sa = self.getLastOldChildSA()
        else:
            child_sa = self.Child_SA
        if child_sa is None or not child_sa.isNegotiatedCompleted:
                raise NoChildSAException
        
        ping = IP(src=child_sa.local_ip, dst=child_sa.remote_ip) / ICMP(type=8)
        if child_sa.protocol == enums.Protocol.ESP:
            prot = ESP 
            sa = SecurityAssociation(prot, spi=struct.unpack('>L', bytes(child_sa.SPIi))[0],
                                    crypt_algo=enums.crypt_algo_map[child_sa.getENCRid()],
                                    crypt_key=child_sa.ei,
                                    auth_algo=enums.auth_algo_map[child_sa.getINTEDid()],
                                    auth_key=child_sa.ai)
        else:
            prot = AH
            sa = SecurityAssociation(prot, spi=struct.unpack('>L', bytes(child_sa.SPIi))[0],
                                    auth_algo=enums.auth_algo_map[child_sa.getINTEDid()],
                                    auth_key=child_sa.ai)
        if child_sa.tunnel_ip is not None:
            sa.tunnel_header=IP(src=child_sa.local_ip, dst=child_sa.tunnel_ip)
            
        IP_data = sa.encrypt(ping, seq_num=child_sa.msgid_out)
        child_sa.msgid_out += 1
        send_message = Ether() / IP_data
        return child_sa, send_message
        
    def process_ipsec_response(self, send_sa, received_message):
        if received_message is None:
            return enums.Response.No_response
        all_child_SA = [self.Child_SA]
        for old_child_sa in self.old_Child_SA.values():
            all_child_SA.append(old_child_sa)
        results = ''
        prot = ESP if send_sa.protocol == enums.Protocol.ESP else AH
        for pack in received_message:
            spi = struct.pack("!L", pack[prot].spi)
            seq = pack[prot].seq
            for sa in all_child_SA:
                # print(spi.hex() + ' | ' + sa.SPIr.hex())
                if spi == sa.SPIr and seq == sa.msgid_in:
                    if sa.SPIr == send_sa.SPIr:
                        results += ('Replay')
                    else:
                        results += ('Replay_misMatch')
                    sa.msgid_in += 1
                    
        if len(results) > 0:
            return results.strip('-')
        return enums.Response.No_response
            
    
    
            
        
        