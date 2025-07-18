from __future__ import print_function
import sys
import os
import os.path
import socket
import struct
import getopt
import binascii
from http import client as httplib
from socketserver import *
from http.server import *
from http.server import SimpleHTTPRequestHandler
from tlslite.api import *
from tlslite.utils.compat import formatExceptionTrace
from tlslite.tlsrecordlayer import TLSRecordLayer
from tlslite.session import Session
from tlslite.constants import *
from tlslite.utils.cryptomath import derive_secret, getRandomBytes, HKDF_expand_label
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.utils.lists import getFirstMatching
from tlslite.errors import *
from tlslite.messages import *
from tlslite.mathtls import *
from tlslite.handshakesettings import HandshakeSettings, KNOWN_VERSIONS, CURVE_ALIASES
from tlslite.handshakehashes import HandshakeHashes
from tlslite.utils.tackwrapper import *
from tlslite.utils.deprecations import deprecated_params
from tlslite.keyexchange import KeyExchange, RSAKeyExchange, DHE_RSAKeyExchange, \
        ECDHE_RSAKeyExchange, SRPKeyExchange, ADHKeyExchange, \
        AECDHKeyExchange, FFDHKeyExchange, ECDHKeyExchange
from tlslite.handshakehelpers import HandshakeHelpers
from tlslite.utils.cipherfactory import createAESCCM, createAESCCM_8, \
        createAESGCM, createCHACHA20
from TLSMapper.helpers import SIG_ALL, RSA_SIG_ALL, AutoEmptyExtension, \
        key_share_gen, psk_session_ext_gen, \
        psk_ext_updater
from tlslite.extensions import TLSExtension, RenegotiationInfoExtension, \
        ClientKeyShareExtension, StatusRequestExtension
from TLSMapper.TLSFuzzer import *
from TLSMapper.random_fuzz import *
import xml.etree.ElementTree as ET
import xml.dom.minidom
from datetime import datetime

class TLSClient13(TLSRecordLayer):
    
    def __init__(self, sock, ciphersuites=None, privateKey=None, cert_chain=None, old_session=None):
        TLSRecordLayer.__init__(self, sock)
        self.serverSigAlg = None
        self.ecdhCurve = None
        self.dhGroupSize = None
        self.extendedMasterSecret = False       
        self._clientRandom = bytearray(0)
        self._serverRandom = bytearray(0)
        self.session_id = bytearray(0)
        self.next_proto = None
        self._ccs_sent = False
        self._peer_record_size_limit = None
        self._pha_supported = False
        self.ciphersuites=ciphersuites
        self.sig_scheme_alg=None
        self.version=(3,4)
        self._cipherSuite = None
        self.CH=ClientHello()
        self.SH=ServerHello()
        self.SH.cipher_suite = ciphersuites[0]
        self.SC=None
        self.SKE=None
        self.CR=None
        self.premasterSecret=bytearray(0)
        self.masterSecret=bytearray(0)
        self.client_verify_data=bytearray(0)
        self.server_verify_data=bytearray(0)
        self.prf_name='sha256'
        self.prf_size=32
        self.early_secret=bytearray(self.prf_size)
        self.handshake_secret=bytearray(self.prf_size)
        self.master_secret=bytearray(self.prf_size)
        self.sr_handshake_traffic_secret=bytearray(self.prf_size)
        self.cl_handshake_traffic_secret=bytearray(self.prf_size)
        self.exporter_master_secret=None
        self.resumption_master_secret=None
        self.cl_app_traffic=bytearray(self.prf_size)
        self.sr_app_traffic=bytearray(self.prf_size)
        self.server_finish_hs=None
        self.psk_only=False
        self.logfile=None
        self.pre_set_extensions = None
        self.extensions = None
        self.settings = None
        self.privateKey = privateKey
        self.cert_chain = cert_chain
        self.server_finish_received = False
        self.post_handshake = False
        self.hrr=False
        self.nst=None
        self._ch_hh=None
        self.old_session = old_session
        
        # for fuzz
        self.fuzz_letter = None
        self.fuzz_flag = False
        self.RF=None
        self.LOG=None
        # for ltlfuzz
        self.fuzzer = TLS_fuzzer()
        self.fuzz_contents = ET.Element("fuzz_recored")
        self.fuzz_replay_content = None
        self.current_number = 0
        self.fuzz_mode = False
        self.fuzz_replay_mode = False

        #for debug
        self.key_log_write = False
        self.key_log_file = None
    
    #for debug
    def write_key_log(self, key_name, client_random, server_random, key):
        file = open(self.key_log_file, "a")
        strr=key_name+' '+client_random.hex() +' '+ key.hex() +'\n'
        # print(strr)
        file.write(strr)
        file.close()
    

    def reset_packet_buffer(self):
        pass
    
    def save_pcap(self, pcap_filename_prefix):
        pass
        
    def save_fuzz_plain(self, filename):
        xml_content = ET.tostring(self.fuzz_contents, encoding='utf-8')
        dom = xml.dom.minidom.parseString(xml_content)
        pretty_xml = dom.toprettyxml()
        with open(filename, 'w') as f:
            f.write(pretty_xml)
        
    def sendAndRecv(self, symbol):
        if symbol == 'ClientHello':
            message = self.generateClientHello()
        elif symbol == 'ChangeCipherSpec':
            message = self.generateChangeCipherSpec()
        elif symbol == 'Certificate':
            if self.privateKey is None or self.cert_chain is None:
                return 'NoClientCert'
            message = self.generateClientCertificate()
        elif symbol == 'CertificateVerify':
            if self.privateKey is None or self.cert_chain is None:
                return 'NoClientCert'
            message = self.generateCertificateVerify()
            if not message:
                return 'SigFailed'
        elif symbol == 'Finish':
            message = self.generateClientFinished()
        elif symbol == 'ApplicationData':
            message = self.generateAppData()
        elif symbol == 'ClosureAlert':
            message = self.generateClosureAlert()
        elif symbol == 'ErrorAlert':
            message = self.generateErrorAlert()
        elif symbol == 'CertificateRequest':
            message = self.generateCertificateRequest()
        elif symbol == 'TLS13ReClientHello':
            message = self.TLS13ReClientHello()
        elif symbol == 'ClientHelloEmtyKeyShare':            
            message = self.generateClientHelloEmtyKeyShare()
        elif symbol == 'KeyUpdate':
            message = self.generateKeyUpdate()        
        elif symbol =="ResumptionClientHello":
            # message = self.generateResumptionClientHello()
            try:
                message = self.generateResumptionClientHello()
            except:
                return "NoSessionBefore"
        else:
            return 'UnSupported'
        # print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        # perform fuzz and save fuzz content  
        self.current_number += 1
        fuzz_content = ET.SubElement(self.fuzz_contents, f'fuzzed_number_{self.current_number}')
        if self.fuzz_mode:
            t, v = self.fuzzer.fuzzMessage(symbol, message)
        elif self.fuzz_replay_mode:
            try:
                history_fuzz_content = self.fuzz_replay_content.find(f'fuzzed_number_{self.current_number}')
                fuzz_symbol = history_fuzz_content.find('symbol').text
                fuzz_type = history_fuzz_content.find('fuzz_type').text
                fuzz_value = history_fuzz_content.find('fuzz_value').text
            except Exception as e:
                print(e)
                pass
            if fuzz_symbol != symbol:
                raise Exception('fuzz_symbol do not match symbol')
            t, v = self.fuzzer.fuzzMessage(symbol, message, fuzz_type, fuzz_value)
        if self.fuzz_mode or self.fuzz_replay_mode:
            ET.SubElement(fuzz_content, 'symbol').text = str(symbol)
            ET.SubElement(fuzz_content, 'fuzz_type').text = str(t)
            ET.SubElement(fuzz_content, 'fuzz_value').text = str(v)
        # print(self.sock)
        if symbol == 'ResumptionClientHello':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(('127.0.0.1',4433))
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            session=[self.resumption_master_secret,self.nst]
            ext = self.extensions
            nst = self.nst
            SH = self.SH
            # print(self.extensions)
            if self.fuzz_flag == True:
                x=self.fuzz_letter
            self.__init__(sock=sock,ciphersuites=[self._cipherSuite], privateKey=self.privateKey, cert_chain=self.cert_chain, old_session=session) 
            self.settings=HandshakeSettings().validate()
            if self.fuzz_flag == True and x != None:
                self.fuzz_letter = x
                self.fuzz_flag = True
            self.CH = message
            self.SH =SH
            self.extensions = ext
            self.nst = nst
            # print(message.Extension)
            # for i in message.extensions:
            #     print(i)
            # print(dir(message.getExtension))
            self._clientRandom = message.random
            
            # self.CH=ClientHello()
            # self.SH=ServerHello() 
            # print(self.sock)
        try:
            # print(symbol,self.fuzz_letter)
            if self.fuzz_flag == True and symbol in self.fuzz_letter:
                self.RF=random_fuzz()
                # print(self.RF)
                # print("!!!!!!!!!!!!!")
                # print("?????????????")
                log_content={'message:':symbol,'fuzz_operator:':None,'packet:':None,'time:':datetime.now().strftime("%Y-%m-%d-%H-%M-%S"),'orign:':None,'recieve:':None}
                self.LOG=log_content
                # print(message)
                for result in self._sendMsg(message, SF=self.RF, fuzz_flag=self.fuzz_flag, log_content=self.LOG):
                    pass
            else:
                # print("????????")
                for result in self._sendMsg(message):
                    pass
            
        except Exception as e:
            return 'SendFailed'
        if symbol == 'ClientHello' or symbol == 'ClientHelloEmtyKeyShare':
            self.CH = message 
            self._clientRandom = message.random
        
        if symbol == 'Finish':
            self._changeWriteState()
            # handshake complete
            if self.server_finish_received:
                self.post_handshake = True
        if symbol =='KeyUpdate':
            # _, sr_app_secret = self._recordLayer.calcTLS1_3KeyUpdate_reciever(
            #                     self.SH.cipher_suite,
            #                     self.cl_app_traffic,
            #                     self.sr_app_traffic)
            self._recordLayer.calcTLS1_3KeyUpdate_reciever(
                                self.SH.cipher_suite,
                                self.cl_app_traffic,
                                self.sr_app_traffic)
            # self._recordLayer.calcTLS1_3KeyUpdate_sender(
            #                     self.SH.cipher_suite,
            #                     self.cl_app_traffic,
            #                     self.sr_app_traffic)
            # self._changeReadState()
            # self._changeWriteState()
            # re = self.process_recieve()

        re = self.process_recieve()
        return re
        
    def set_extensions(self, versions=None, groups=None, sig_algs=None):
        ext = {}
        if versions is None:
            versions = [(3, 4), (3, 3), (3, 2), (3, 1)]
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension().create(versions)
        # ext[ExtensionType.ec_point_formats] = ECPointFormatsExtension().create(ECPointFormat.all)
        # ext[ExtensionType.session_ticket] = AutoEmptyExtension()
        # ext[ExtensionType.encrypt_then_mac] = AutoEmptyExtension()
        # ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        if groups is None:
            groups = [GroupName.secp256r1]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension().create(groups)
        # ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension().create([PskKeyExchangeMode.psk_dhe_ke])
        key_shares = []
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        if self.hrr == False:
            for group in groups:
                key_shares.append(self._genKeyShareEntry(group, self.version))
        if sig_algs is None:
            sig_algs = RSA_SIG_ALL
        # print(sig_algs)
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension().create(sig_algs)
        ext[ExtensionType.cert_type] = ClientCertTypeExtension().create([CertificateType.x509])
        # FOR PSK
        # ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension().create([PskKeyExchangeMode.psk_ke])
        ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
                .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
        # ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
        # print(AutoEmptyExtension)
        # if self.hrr == True:
        #     ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        #         .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
        #     extensions[ExtensionType.psk_key_exchange_modes] = None
            
        #     extensions[ExtensionType.key_share] = None
        #     extensions[ExtensionType.supported_versions] = None
        # print(extensions[ExtensionType.key_share])
        # print(extensions)
        # print(ext)
        self.extensions=ext
    


    def generate_extensions(self):
        """Convert extension generators(a dict) to extension objects(a list)."""
        extensions = []
        if self.pre_set_extensions is None:
            self.set_extensions()
        else:
            self.set_extensions(versions=self.pre_set_extensions[0],groups=self.pre_set_extensions[1],sig_algs=self.pre_set_extensions[2])
        
        for ext_id in self.extensions:
            # print(ext_id)
            if self.extensions[ext_id] is not None:
                if callable(self.extensions[ext_id]):
                    extensions.append(self.extensions[ext_id])
                elif isinstance(self.extensions[ext_id], TLSExtension):
                    extensions.append(self.extensions[ext_id])
                elif self.extensions[ext_id] is AutoEmptyExtension():
                    extensions.append(TLSExtension().create(ext_id,
                                                            bytearray()))
                else:
                    raise ValueError("Bad extension, id: {0}".format(ext_id))
                continue

            if ext_id == ExtensionType.renegotiation_info:
                ext = RenegotiationInfoExtension().create(self.client_verify_data)
            elif ext_id == ExtensionType.status_request:
                ext = StatusRequestExtension().create()
            elif ext_id in (ExtensionType.client_hello_padding,
                            ExtensionType.encrypt_then_mac,
                            ExtensionType.extended_master_secret,
                            ExtensionType.session_ticket,  
                            ExtensionType.post_handshake_auth,  
                            ExtensionType.transparency_info):  
                ext = TLSExtension().create(ext_id, bytearray())
            else:
                raise ValueError("No autohandler for extension {0}"
                                 .format(ExtensionType.toStr(ext_id)))
            extensions.append(ext)
        # print(extensions)
        
        return extensions

    def generateClientHello(self):
        
        # print(session_id,self)
        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)
        # session_id = bytearray()
        # session_id = getRandomBytes(16)
        self.hrr=False
        client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
        clientHello = ClientHello()
        clientHello.create((3,3),
                           client_random,
                           self.session_id,
                           self.ciphersuites,
                           extensions=self.generate_extensions())
        
        if self.settings.pskConfigs:
            # print("?????????????????")
            ext = PreSharedKeyExtension()
            idens = []
            binders = []
            for psk in self.settings.pskConfigs:
                # skip PSKs with no identities as they're TLS1.3 incompatible
                if not psk[0]:
                    continue
                idens.append(PskIdentity().create(psk[0], 0))
                psk_hash = psk[2] if len(psk) > 2 else 'sha256'
                assert psk_hash in set(['sha256', 'sha384'])
                # create fake binder values to create correct length fields
                binders.append(bytearray(32 if psk_hash == 'sha256' else 48))

            if idens:
                ext.create(idens, binders)
                clientHello.extensions.append(ext)
                # for HRR(HelloRetryRequest) case we'll need 1st CH and HRR in handshake hashes,
                # so pass them in, truncated CH will be added by the helpers to
                # the copy of the hashes
                HandshakeHelpers.update_binders(clientHello,
                                                self._handshake_hash,
                                                self.settings.pskConfigs,
                                                self.session.tickets if self.session else None,
                                                self.session.resumptionMasterSecret if self.session else None)
        # print(clientHello.write())
        # print(clientHello)
        return clientHello

    def generateClientHelloEmtyKeyShare(self):
        
        if self.session_id == bytearray(0):
            self.session = None
            self.session_id = getRandomBytes(32)
        # session_id = bytearray()
        # session_id = getRandomBytes(16)
        self.hrr=True
        client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
        clientHello = ClientHello()
        clientHello.create((3,3),
                           client_random,
                           self.session_id,
                           self.ciphersuites,
                           extensions=self.generate_extensions())
        if self.settings.pskConfigs:
            ext = PreSharedKeyExtension()
            idens = []
            binders = []
            for psk in self.settings.pskConfigs:
                # skip PSKs with no identities as they're TLS1.3 incompatible
                if not psk[0]:
                    continue
                idens.append(PskIdentity().create(psk[0], 0))
                psk_hash = psk[2] if len(psk) > 2 else 'sha256'
                assert psk_hash in set(['sha256', 'sha384'])
                # create fake binder values to create correct length fields
                binders.append(bytearray(32 if psk_hash == 'sha256' else 48))

            if idens:
                ext.create(idens, binders)
                clientHello.extensions.append(ext)
                # for HRR(HelloRetryRequest) case we'll need 1st CH and HRR in handshake hashes,
                # so pass them in, truncated CH will be added by the helpers to
                # the copy of the hashes
                HandshakeHelpers.update_binders(clientHello,
                                                self._handshake_hash,
                                                self.settings.pskConfigs,
                                                self.session.tickets if self.session else None,
                                                self.session.resumptionMasterSecret if self.session else None)
        return clientHello
    

    def generateResumptionClientHello(self):
        # closurealert = Alert().create(AlertDescription.close_notify, level=AlertLevel.warning)
        # print(closurealert)
        # try:
        #     for result in self._sendMsg(closurealert):
        #         pass
        # except:
        #     pass
    

        self.resumption_master_secret = derive_secret(self.master_secret,
                                               bytearray(b'res master'),
                                               self._handshake_hash, self.prf_name)
        # print("self.resumption_master_secret",self.resumption_master_secret)

        nst=self.nst
        ident = []
        binder = []
        self._handshake_hash=HandshakeHashes()
        # nst.time is fractional but ticket time should be in ms, not s as the
        # NewSessionTicket.time is
        # print(nst)
        ticket_time = int(time.time() * 1000 - nst.ticket_lifetime * 1000 +
                        nst.ticket_age_add) % 2**32
        ticket_iden = PskIdentity().create(nst.ticket, ticket_time)
        binder_len = self.prf_size

        ident.insert(0, ticket_iden)
        binder.insert(0, bytearray(binder_len))
        # print(self.extensions)
        self.extensions[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(ident, binder)
   
        ext=[]
        for ext_id in self.extensions:
            if self.extensions[ext_id] is not None:
                    ext.append(self.extensions[ext_id])
        # print(ext)
        # ext[0] = SupportedVersionsExtension().create([(3,3),(3,4)])
        ext[0] = SupportedVersionsExtension().create([(3,4)])

        # print(ext)
        client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
        clientHello = ClientHello()
 
        clientHello.create((3,3),
                           client_random,
                           self.session_id,
                           self.ciphersuites,
                           extensions=ext)
        # self.extensions=ext
        

        HandshakeHelpers.update_binders(
            clientHello,
            self._handshake_hash,
            (),
            [nst] if nst else None,
            self.resumption_master_secret)

        return clientHello
        


    def generateChangeCipherSpec(self):
        ccs = ChangeCipherSpec().create()
        return ccs 

    def generateClientCertificate(self):  
        if self.SH == None:
            certificate_type = CertificateType.x509
        else:
            certificate_type = self.SH.certificate_type
        client_certificate = Certificate(certificate_type, self.version)
        client_certificate.create(self.cert_chain)
        return client_certificate

    def generateCertificateVerify(self):
        try:
            valid_sig_algs = self.CR.supported_signature_algs
        except:
            valid_sig_algs = RSA_SIG_ALL
        availSigAlgs = self._sigHashesToList(self.settings, self.privateKey,
                                             self.cert_chain, version=(3, 4))
        signature_scheme = getFirstMatching(availSigAlgs, valid_sig_algs)
        scheme = SignatureScheme.toRepr(signature_scheme)
        signature_scheme = getattr(SignatureScheme, scheme)
        signature_context = KeyExchange.calcVerifyBytes((3, 4), self._handshake_hash,
                                                        signature_scheme, None, None,
                                                        None, self.prf_name, b'client')

        if signature_scheme in (SignatureScheme.ed25519, SignatureScheme.ed448):
            pad_type = None
            hash_name = "intrinsic"
            salt_len = None
            sig_func = self.privateKey.hashAndSign
            ver_func = self.privateKey.hashAndVerify
        elif signature_scheme[1] == SignatureAlgorithm.ecdsa:
            pad_type = None
            hash_name = HashAlgorithm.toRepr(signature_scheme[0])
            salt_len = None
            sig_func = self.privateKey.sign
            ver_func = self.privateKey.verify
        else:
            pad_type = SignatureScheme.getPadding(scheme)
            hash_name = SignatureScheme.getHash(scheme)
            salt_len = getattr(hashlib, hash_name)().digest_size
            sig_func = self.privateKey.sign
            ver_func = self.privateKey.verify

        signature = sig_func(signature_context,
                             pad_type,
                             hash_name,
                             salt_len)
        if not ver_func(signature, signature_context,
                        pad_type,
                        hash_name,
                        salt_len):
            # for result in self._sendError(
            #         AlertDescription.internal_error,
            #         "Certificate Verify signature failed"):
            #     yield result
            return None

        certificateVerify = CertificateVerify(self.version)
        certificateVerify.create(signature, signature_scheme)
        return certificateVerify

    def generateClientFinished(self):
        temp = derive_secret(self.handshake_secret, bytearray(b'derived'), None, self.prf_name)
        self.master_secret = secureHMAC(temp, bytearray(self.prf_size), self.prf_name)
        self.cl_app_traffic = derive_secret(self.master_secret, bytearray(b'c ap traffic'),
                                       self.server_finish_hs, self.prf_name)
        if self.sr_app_traffic is None:
            self.sr_app_traffic = derive_secret(self.master_secret, bytearray(b's ap traffic'),
                                                self.server_finish_hs, self.prf_name)
        self.exporter_master_secret = derive_secret(self.master_secret,
                                               bytearray(b'exp master'),
                                               self._handshake_hash, self.prf_name)
        # self.resumption_master_secret = derive_secret(self.master_secret,
        #                                        bytearray(b'res master'),
        #                                        self._handshake_hash, self.prf_name)
        # print(self.SH.cipher_suite,self.cl_app_traffic, self.sr_app_traffic)
        self._recordLayer.calcTLS1_3PendingState(
            self.SH.cipher_suite,
            self.cl_app_traffic,
            self.sr_app_traffic,
            ['python'])
        
        if self.key_log_write == True:
            try:
                self.write_key_log('SERVER_HANDSHAKE_TRAFFIC_SECRET',self._clientRandom,self._serverRandom,self.sr_handshake_traffic_secret)
                self.write_key_log('CLIENT_HANDSHAKE_TRAFFIC_SECRET',self._clientRandom,self._serverRandom,self.cl_handshake_traffic_secret)
                self.write_key_log('EXPORTER_SECRET',self._clientRandom,self._serverRandom,self.exporter_master_secret)
                self.write_key_log('SERVER_TRAFFIC_SECRET_0',self._clientRandom,self._serverRandom,self.sr_app_traffic)
                self.write_key_log('CLIENT_TRAFFIC_SECRET_0',self._clientRandom,self._serverRandom,self.cl_app_traffic)
            except:
                pass


        # print("sr_handshake_traffic_secret",self.sr_handshake_traffic_secret.hex())
        # print("cl_handshake_traffic_secret",self.cl_handshake_traffic_secret)
        # print("cl_app_traffic",self.cl_app_traffic)
        # print("sr_app_traffic",self.sr_app_traffic)


        cl_finished_key = HKDF_expand_label(self.cl_handshake_traffic_secret,
                                            b"finished", b'',
                                            self.prf_size, self.prf_name)
        cl_verify_data = secureHMAC(
            cl_finished_key,
            self._handshake_hash.digest(self.prf_name),
            self.prf_name)
        client_finished = Finished(self.version, self.prf_size)
        client_finished.create(cl_verify_data)
        
        return client_finished

    def generateClosureAlert(self):
        closurealert = Alert().create(AlertDescription.close_notify, level=AlertLevel.warning)
        return closurealert
            
    def generateErrorAlert(self):
        erroralert = Alert().create(AlertDescription.decrypt_error, level=AlertLevel.fatal)
        return erroralert
    
    def generateCertificateRequest(self):
        extensions=[SignatureAlgorithmsExtension().create(RSA_SIG_ALL)]
        certificateRequest = CertificateRequest(self.version).create(extensions)
        return certificateRequest
            
    def generateAppData(self):
        appdata = ApplicationData().create(b"GET / HTTP/1.1\r\nHost: testserver.com\r\n\r\n") # for wolfssl
        # print(appdata.write())
        # appdata = ApplicationData().create(b"GET / HTTP/1.0\n\n") # for openssl
        return appdata
    
    def generateKeyUpdate(self):
        key_update = KeyUpdate().create(KeyUpdateMessageType.update_requested)
        
        # self._changeReadState()
        # self._changeWriteState()
        return key_update
    
    def ResetHandshakeHashes(self):
        self._handshake_hash = HandshakeHashes()

    def TLS13ReClientHello(self):
        # print(self.key)
        self.ResetHandshakeHashes()
        
    def _check_certchain_with_settings(self, cert_chain, settings):
        """
        Verify that the key parameters match enabled ones.

        Checks if the certificate key size matches the minimum and maximum
        sizes set or that it uses curves enabled in settings
        """
        #Get and check public key from the cert chain
        publicKey = cert_chain.getEndEntityPublicKey()
        cert_type = cert_chain.x509List[0].certAlg
        if cert_type == "ecdsa":
            curve_name = publicKey.curve_name
            for name, aliases in CURVE_ALIASES.items():
                if curve_name in aliases:
                    curve_name = name
                    break

            if self.version <= (3, 3) and curve_name not in settings.eccCurves:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Peer sent certificate with curve we did not "
                        "advertise support for: {0}".format(curve_name)):
                    yield result
            if self.version >= (3, 4):
                if curve_name not in ('secp256r1', 'secp384r1', 'secp521r1'):
                    for result in self._sendError(
                            AlertDescription.illegal_parameter,
                            "Peer sent certificate with curve not supported "
                            "in TLS 1.3: {0}".format(curve_name)):
                        yield result
                if curve_name == 'secp256r1':
                    sig_alg_for_curve = 'sha256'
                elif curve_name == 'secp384r1':
                    sig_alg_for_curve = 'sha384'
                else:
                    assert curve_name == 'secp521r1'
                    sig_alg_for_curve = 'sha512'
                if sig_alg_for_curve not in settings.ecdsaSigHashes:
                    for result in self._sendError(
                            AlertDescriptimasteron.illegal_parameter,
                            "Peer selected certificate with ECDSA curve we "
                            "did not advertise support for: {0}"
                            .format(curve_name)):
                        yield result
        elif cert_type in ("Ed25519", "Ed448"):
            if self.version < (3, 3):
                for result in self._sendError(
                        AlertDescription.illegal_parameter,
                        "Peer sent certificate incompatible with negotiated "
                        "TLS version"):
                    yield result
            if cert_type not in settings.more_sig_schemes:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Peer sent certificate we did not advertise support "
                        "for: {0}".format(cert_type)):
                    yield result

        else:
            # for RSA and DSA keys
            if len(publicKey) < settings.minKeySize:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Other party's public key too small: %d" %
                        len(publicKey)):
                    yield result
            if len(publicKey) > settings.maxKeySize:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Other party's public key too large: %d" %
                        len(publicKey)):
                    yield result
        yield publicKey

    def _clientGetKeyFromChain(self, certificate, settings, tack_ext=None):
        #Get and check cert chain from the Certificate message
        cert_chain = certificate.cert_chain
        if not cert_chain or cert_chain.getNumCerts() == 0:
            for result in self._sendError(
                    AlertDescription.illegal_parameter,
                    "Other party sent a Certificate message without "\
                    "certificates"):
                yield result

        for result in self._check_certchain_with_settings(
                cert_chain,
                settings):
            if result in (0, 1):
                yield result
            else: break
        public_key = result

        # If there's no TLS Extension, look for a TACK cert
        if tackpyLoaded:
            if not tack_ext:
                tack_ext = cert_chain.getTackExt()
         
            # If there's a TACK (whether via TLS or TACK Cert), check that it
            # matches the cert chain   
            if tack_ext and tack_ext.tacks:
                for tack in tack_ext.tacks:
                    if not cert_chain.checkTack(tack):
                        for result in self._sendError(  
                                AlertDescription.illegal_parameter,
                                "Other party's TACK doesn't match their public key"):
                                yield result

        yield public_key, cert_chain, tack_ext

    @classmethod
    def _genKeyShareEntry(cls, group, version):
        """Generate KeyShareEntry object from randomly selected private value.
        """
        kex = cls._getKEX(group, version)
        private = kex.get_random_private_key()
        share = kex.calc_public_value(private)
        return KeyShareEntry().create(group, share, private)

    @staticmethod
    def _getKEX(group, version):
        """Get object for performing key exchange."""
        if group in GroupName.allFF:
            return FFDHKeyExchange(group, version)
        return ECDHKeyExchange(group, version)
    
    @staticmethod
    def _getPRFParams(cipher_suite):
        """Return name of hash used for PRF and the hash output size."""
        if cipher_suite in CipherSuite.sha384PrfSuites:
            return 'sha384', 48
        return 'sha256', 32

    def server_extensions_is_wrong(self, smsg_type, server_extensions):
        client_extensions = [ens.extType for ens in self.CH.extensions]
        for en in server_extensions:
            if en not in client_extensions:
                if smsg_type == HandshakeType.hello_retry_request and en == ExtensionType.cookie:
                    continue
                return True
        if ExtensionType.psk_key_exchange_modes in server_extensions:
            return True
        if ExtensionType.post_handshake_auth in server_extensions:
            return True
        return False
    
    @staticmethod
    def _curve_name_to_hash_name(curve_name):
        """Find the matching hash given the curve name, as specified in TLS 1.3."""
        if curve_name == "NIST256p":
            return "sha256"
        if curve_name == "NIST384p":
            return "sha384"
        if curve_name == "NIST521p":
            return "sha512"
        raise ValueError("Curve {0} is not allowed in TLS 1.3 "
                        "(wrong name? please use python-ecdsa names)"
                        .format(curve_name))
        
    def process_recieve(self):
        time.sleep(0.3)
        receive_msg = ''
        while True:
            try:
                for result in self._getMsg(ContentType.all, HandshakeType.all):
                    pass
            except Exception as e:
                break
            recordHeader, p = result
            # print(result,recordHeader.type)
            if recordHeader.type == ContentType.change_cipher_spec:
                ccs = ChangeCipherSpec().parse(p)
                receive_msg += '-ChangeCipherSpec'
            if recordHeader.type == ContentType.application_data:
                appdata = ApplicationData().parse(p)
                # print(appdata.write())
                receive_msg += '-AppliciationData'
            if recordHeader.type == ContentType.alert:
                alert = Alert().parse(p)
                receive_msg += '-' + alert.descriptionName
            if recordHeader.type == ContentType.handshake:
                subType = p.get(1)                
                if subType == HandshakeType.client_hello:
                    self._handshake_hash.update(p.bytes)
                    receive_msg += '-ClientHello'
                if subType == HandshakeType.key_update:
                    if p.get(2) == 0:
                        receive_msg += '-keyUpdate_not_req'
                    if p.get(2) == 1:
                        receive_msg += '-keyUpdate_req'
                    self._recordLayer.calcTLS1_3KeyUpdate_sender(
                                self.SH.cipher_suite,
                                self.cl_app_traffic,
                                self.sr_app_traffic)
                    # self._changeReadState()
                    # self._changeWriteState()
                # state.key['server application traffic secret'] = sr_app_secret


                if subType == HandshakeType.hello_retry_request:
                    self._handshake_hash.update(p.bytes)
                    helloRetryRequest = ServerHello().parse(p)
                    server_ens = [ens.extType for ens in helloRetryRequest.extensions]
                    if self.server_extensions_is_wrong(subType, server_ens):
                        receive_msg += '-HelloRetryRequestWithWrongENs'
                    else:
                        receive_msg += '-HelloRetryRequest'
                if subType == HandshakeType.server_hello:
                    serverHello = ServerHello().parse(p)
                    self.SH = serverHello
                    server_ens = [ens.extType for ens in serverHello.extensions]
                    sr_kex = serverHello.getExtension(ExtensionType.key_share)
                    # print(self.hrr)
                    if self.hrr ==True:
                        prf_name, prf_size = self._getPRFParams(serverHello.cipher_suite)
                        self._ch_hh = self._handshake_hash.copy()
                        ch_hash = self._ch_hh.digest(prf_name)
                        new_hh = HandshakeHashes()
                        writer = Writer()
                        writer.add(HandshakeType.message_hash, 1)
                        writer.addVarSeq(ch_hash, 1, 3)
                        new_hh.update(writer.bytes)
                        # print("writer.bytes",writer.bytes)
                        # print(p)
                        new_hh.update(p.bytes)

                        self._handshake_hash = new_hh

                        receive_msg += '-ServerHelloRetryRequest'
                        # print(serverHello.extensions)
                        # print(dir(serverHello.extensions))
                        # sr_kex = sr_kex.server_share
                        # self.ecdhCurve = sr_kex.group
                        # self.ecdhCurve = self.SH.group
                        # self.version = self.SH.version
                    else:
                        self._handshake_hash.update(p.bytes)
                        sr_psk = serverHello.getExtension(ExtensionType.pre_shared_key)
                        self._serverRandom = serverHello.random
                        self._cipherSuite = serverHello.cipher_suite
                        self.prf_Name, self.prf_size = self._getPRFParams(serverHello.cipher_suite)
                        group_is_wrong = False
                        if not sr_kex and not sr_psk:
                            # raise TLSIllegalParameterException("Server did not select PSK nor an (EC)DH group")
                            group_is_wrong = True
                        if sr_kex:
                            sr_kex = sr_kex.server_share
                            self.ecdhCurve = sr_kex.group
                            # print(self.CH)
                            cl_key_share_ex = self.CH.getExtension(ExtensionType.key_share)
                            cl_kex = next((i for i in cl_key_share_ex.client_shares
                                        if i.group == sr_kex.group), None)
                            if cl_kex is None:
                                # raise TLSIllegalParameterException("Server selected not advertised group.")
                                group_is_wrong = True
                            kex = self._getKEX(sr_kex.group, self.version)
                            shared_sec = kex.calc_shared_key(cl_kex.private, sr_kex.key_exchange)
                        else:
                            shared_sec = bytearray(self.prf_size)
                        
                        # check server extensions
                        client_ens = [ens.extType for ens in self.CH.extensions]
                        if self.server_extensions_is_wrong(subType, server_ens) or group_is_wrong:
                            receive_msg += '-ServerHelloWithWrongENs'
                        elif sr_psk and ExtensionType.psk_key_exchange_modes not in client_ens:
                            receive_msg += '-ServerHelloWithWrongENs'                            
                        elif sr_kex and ExtensionType.key_share not in client_ens:
                            receive_msg += '-ServerHelloWithWrongENs'
                        elif sr_psk:
                            receive_msg += '-ServerHelloPSK'
                        else:
                            receive_msg += '-ServerHello'

                        # if server agreed to perform resumption, find the matching secret key
                        resuming = False

                        if sr_psk:
                            clPSK = self.CH.getExtension(ExtensionType.pre_shared_key)
                            ident = clPSK.identities[sr_psk.selected]
                            psk = [i[1] for i in self.settings.pskConfigs if i[0] == ident.identity]
                            if psk:
                                psk = psk[0]
                            else:
                                resuming = True
                                psk = HandshakeHelpers.calc_res_binder_psk(
                                    ident, self.old_session[0],
                                    [self.old_session[1]])
                                # psk = HandshakeHelpers.calc_res_binder_psk(
                                #     ident, session.resumptionMasterSecret,
                                #     session.tickets)
                        else:
                            psk = bytearray(self.prf_size)

                            # Early Secret
                        self.early_secret = secureHMAC(bytearray(self.prf_size), psk, self.prf_Name)
                    
                        # Handshake Secret
                        temp = derive_secret(self.early_secret, bytearray(b'derived'),
                                            None, self.prf_Name)
                        self.handshake_secret = secureHMAC(temp, shared_sec, self.prf_Name)
                        # print(self._handshake_hash._handshake_buffer.hex())

                        self.sr_handshake_traffic_secret = derive_secret(self.handshake_secret,
                                                                    bytearray(b's hs traffic'),
                                                                    self._handshake_hash,
                                                                    self.prf_Name)
                        self.cl_handshake_traffic_secret = derive_secret(self.handshake_secret,
                                                                    bytearray(b'c hs traffic'),
                                                                    self._handshake_hash,
                                                                    self.prf_Name)

                        #WolfSSL using this
                        self._recordLayer.calcTLS1_3PendingState(
                                self.SH.cipher_suite,
                                self.cl_handshake_traffic_secret,
                                self.sr_handshake_traffic_secret,
                                self.settings.cipherImplementations)
                        self._changeReadState()
                        self._changeWriteState()
                        
                if subType == HandshakeType.encrypted_extensions:
                    self._handshake_hash.update(p.bytes)
                    encryptedExtensions = EncryptedExtensions().parse(p)
                    server_ens = [ens.extType for ens in encryptedExtensions.extensions]
                    if self.server_extensions_is_wrong(subType, server_ens):
                        receive_msg += '-EncryptedExtensionsWithWrongENs'
                    else:
                        receive_msg += '-EncryptedExtensions'
                if subType == HandshakeType.certificate_request:
                    self._handshake_hash.update(p.bytes)
                    self.CR = CertificateRequest(self.version).parse(p)
                    if self.post_handshake:
                        receive_msg += '-CertificateRequestPostHandshake' 
                    else:
                        receive_msg += '-CertificateRequest'                
                if subType == HandshakeType.certificate:
                    self._handshake_hash.update(p.bytes)
                    self.SC = Certificate(self.SH.certificate_type, self.version).parse(p)
                    receive_msg += '-Certificate'
                    srv_cert_verify_hh = self._handshake_hash.copy()
                if subType == HandshakeType.certificate_verify:
                    self._handshake_hash.update(p.bytes)
                    certificate_verify = CertificateVerify(self.version).parse(p)
                    receive_msg += '-CertificateVerify'
                    signature_scheme = certificate_verify.signatureAlgorithm
                    self.serverSigAlg = signature_scheme
                    signature_context = KeyExchange.calcVerifyBytes((3, 4),
                                                                    srv_cert_verify_hh,
                                                                    signature_scheme,
                                                                    None, None, None,
                                                                    self.prf_Name, b'server')
                    for result in self._clientGetKeyFromChain(self.SC, self.settings):
                        pass
                    publicKey, serverCertChain, tackExt = result
                    if signature_scheme in (SignatureScheme.ed25519, SignatureScheme.ed448):
                        pad_type = None
                        hash_name = "intrinsic"
                        salt_len = None
                        method = publicKey.hashAndVerify
                    elif signature_scheme[1] == SignatureAlgorithm.ecdsa:
                        # print(publicKey.curve_name)
                        pad_type = None
                        hash_name = HashAlgorithm.toRepr(signature_scheme[0])
                        matching_hash = self._curve_name_to_hash_name(
                            publicKey.curve_name)
                        if hash_name != matching_hash:
                            raise TLSIllegalParameterException(
                                "server selected signature method invalid for the "
                                "certificate it presented (curve mismatch)")

                        salt_len = None
                        method = publicKey.verify
                    else:
                        scheme = SignatureScheme.toRepr(signature_scheme)
                        pad_type = SignatureScheme.getPadding(scheme)
                        hash_name = SignatureScheme.getHash(scheme)
                        salt_len = getattr(hashlib, hash_name)().digest_size
                        method = publicKey.verify

                    transcript_hash = self._handshake_hash.digest(self.prf_Name)
                    
                if subType == HandshakeType.finished:
                    self._handshake_hash.update(p.bytes)
                    receive_msg += '-Finished'
                    self.server_finish_hs = self._handshake_hash.copy()      
                    self.server_finish_received = True              
                    
                    temp = derive_secret(self.handshake_secret, bytearray(b'derived'), None, self.prf_name)
                    self.master_secret = secureHMAC(temp, bytearray(self.prf_size), self.prf_name)
                    self.sr_app_traffic = derive_secret(self.master_secret, bytearray(b's ap traffic'),
                                                self.server_finish_hs, self.prf_name)
                    self.exporter_master_secret = derive_secret(self.master_secret,
                                                        bytearray(b'exp master'),
                                                        self._handshake_hash, self.prf_name)
                    self._recordLayer.calcTLS1_3PendingState(
                        self.SH.cipher_suite,
                        self.cl_handshake_traffic_secret,
                        self.sr_app_traffic,
                        ['python'])
                    self._changeReadState()
                    
                if subType == HandshakeType.new_session_ticket:
                    # self._handshake_hash.update(p.bytes)
                    newSessionTicket = NewSessionTicket().parse(p)
                    self.nst=newSessionTicket
                    # print(self.nst)
                    if newSessionTicket.ticket_lifetime > 604800:
                        receive_msg += '-NewSessionTicketWrongLifetime'
                    else:
                        receive_msg += '-NewSessionTicket'
                    
                if subType == HandshakeType.end_of_early_data:
                    receive_msg += '-EndofEarlyData'
                    
        return 'NoResponse' if receive_msg == '' else receive_msg.strip('-')
    
    @staticmethod
    def _sigHashesToList(settings, privateKey=None, certList=None,
                         version=(3, 3)):
        """Convert list of valid signature hashes to array of tuples"""
        certType = None
        publicKey = None
        if certList and certList.x509List:
            certType = certList.x509List[0].certAlg
            publicKey = certList.x509List[0].publicKey

        sigAlgs = []

        if not certType or certType == "Ed25519" or certType == "Ed448":
            for sig_scheme in settings.more_sig_schemes:
                if version < (3, 3):
                    # EdDSA is supported only in TLS 1.2 and 1.3
                    continue
                if certType and sig_scheme != certType:
                    continue
                sigAlgs.append(getattr(SignatureScheme, sig_scheme.lower()))

        if not certType or certType == "ecdsa":
            for hashName in settings.ecdsaSigHashes:
                # only SHA256, SHA384 and SHA512 are allowed in TLS 1.3
                if version > (3, 3) and hashName in ("sha1", "sha224"):
                    continue

                # in TLS 1.3 ECDSA key curve is bound to hash
                if publicKey and version > (3, 3):
                    curve = publicKey.curve_name
                    matching_hash = TLSConnection._curve_name_to_hash_name(
                        curve)
                    if hashName != matching_hash:
                        continue

                sigAlgs.append((getattr(HashAlgorithm, hashName),
                                SignatureAlgorithm.ecdsa))

        if not certType or certType == "dsa":
            for hashName in settings.dsaSigHashes:
                if version > (3, 3):
                    continue

                sigAlgs.append((getattr(HashAlgorithm, hashName),
                                SignatureAlgorithm.dsa))

        if not certType or certType in ("rsa", "rsa-pss"):
            for schemeName in settings.rsaSchemes:
                # pkcs#1 v1.5 signatures are not allowed in TLS 1.3
                if version > (3, 3) and schemeName == "pkcs1":
                    continue

                for hashName in settings.rsaSigHashes:
                    # rsa-pss certificates can't be used to make PKCS#1 v1.5
                    # signatures
                    if certType == "rsa-pss" and schemeName == "pkcs1":
                        continue
                    try:
                        # 1024 bit keys are too small to create valid
                        # rsa-pss-SHA512 signatures
                        if schemeName == 'pss' and hashName == 'sha512'\
                                and privateKey and privateKey.n < 2**2047:
                            continue
                        # advertise support for both rsaEncryption and RSA-PSS OID
                        # key type
                        if certType != 'rsa-pss':
                            sigAlgs.append(getattr(SignatureScheme,
                                                   "rsa_{0}_rsae_{1}"
                                                   .format(schemeName, hashName)))
                        if certType != 'rsa':
                            sigAlgs.append(getattr(SignatureScheme,
                                                   "rsa_{0}_pss_{1}"
                                                   .format(schemeName, hashName)))
                    except AttributeError:
                        if schemeName == 'pkcs1':
                            sigAlgs.append((getattr(HashAlgorithm, hashName),
                                            SignatureAlgorithm.rsa))
                        continue
        return sigAlgs





