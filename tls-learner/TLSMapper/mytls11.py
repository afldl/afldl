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
from TLSMapper.helpers import SIG_ALL, RSA_SIG_ALL, AutoEmptyExtension
from tlslite.extensions import TLSExtension, RenegotiationInfoExtension, \
        ClientKeyShareExtension, StatusRequestExtension
from TLSMapper.TLSFuzzer import *
import xml.etree.ElementTree as ET
import xml.dom.minidom


class TLSClient11(TLSRecordLayer):
    
    def __init__(self, sock, ciphersuites=None, privateKey=None, cert_chain=None):
        TLSRecordLayer.__init__(self, sock)
        self.serverSigAlg = None
        self.ecdhCurve = None
        self.dhGroupSize = None
        self.extendedMasterSecret = False
        
        self._clientRandom = bytearray(0)
        self._serverRandom = bytearray(0)
        self.next_proto = None
        self._ccs_sent = False
        self._peer_record_size_limit = None
        self._pha_supported = False
        self.ciphersuites=ciphersuites
        self.sig_scheme_alg=None
        self.version=(3,2)
        self._cipherSuite = None
        self.CH=None
        self.SH=None
        # self.SH.cipher_suite = ciphersuites[0]
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
        
        # for fuzz
        self.fuzzer = TLS_fuzzer()
        self.fuzz_contents = ET.Element("fuzz_recored")
        self.fuzz_replay_content = None
        self.current_number = 0
        self.fuzz_mode = False
        self.fuzz_replay_mode = False

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
        # print(1)
        if symbol == 'ClientHelloDHE':
            self.ciphersuites= [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
            message = self.generateClientHello()
            
        elif symbol == 'ClientHelloRSA':
            self.ciphersuites= [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
            message = self.generateClientHello()
        elif symbol == 'ClientHello':
            # self.ciphersuites= [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            #                     CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
            message = self.generateClientHello()   
            # print(message) 
        elif symbol == 'ClientKeyExchange':
            message = self.generateClientKeyExchange()
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
        elif symbol == 'TLS12ReClientHello':
            message = self.TLS12ReClientHello()
        else:
            return 'UnSupported'
        
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
            
        try:
            for result in self._sendMsg(message):
                pass
        except Exception as e:
            return 'SendFailed'
        if symbol == 'ClientHello':
            self.CH = message 
            self._clientRandom = message.random
        if symbol == 'ChangeCipherSpec':
            self.changestate()
        if symbol == 'Finish':
            # self.changestate()
            # self._changeWriteState()
            # handshake complete
            if self.server_finish_received:
                self.post_handshake = True
        re = self.process_recieve()
        return re
        ext = {ExtensionType.renegotiation_info: None}


    def set_extensions(self, versions=None, groups=None, sig_algs=None):
        ext = {}
        if versions is None:
            versions = [(3, 2)]
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension().create(versions)
        # ext[ExtensionType.ec_point_formats] = ECPointFormatsExtension().create(ECPointFormat.all)
        # ext[ExtensionType.session_ticket] = AutoEmptyExtension()
        # ext[ExtensionType.encrypt_then_mac] = AutoEmptyExtension()
        # ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        if groups is None:
            groups = [GroupName.secp256r1]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension().create(groups)
        # ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension().create([PskKeyExchangeMode.psk_dhe_ke])
        # key_shares = []
        # ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        # for group in groups:
        #     key_shares.append(self._genKeyShareEntry(group, self.version))
        if sig_algs is None:
            sig_algs = RSA_SIG_ALL
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension().create(sig_algs)
        # # ext[ExtensionType.cert_type] = ClientCertTypeExtension().create([CertificateType.x509])
        # ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        # .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
        # ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
        # print(AutoEmptyExtension)
        self.extensions=ext

    def generate_extensions(self):
        """Convert extension generators to extension objects."""
        # print(self.extensions)
        extensions = []
        if self.pre_set_extensions is None:
            self.set_extensions()
        else:
            self.set_extensions(versions=self.pre_set_extensions[0],groups=self.pre_set_extensions[1],sig_algs=self.pre_set_extensions[2])
        
        for ext_id in self.extensions:
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
                ext = RenegotiationInfoExtension()\
                    .create(self.client_verify_data)
            elif ext_id == ExtensionType.status_request:
                ext = StatusRequestExtension().create()
            elif ext_id in (ExtensionType.client_hello_padding,
                            ExtensionType.encrypt_then_mac,
                            ExtensionType.extended_master_secret,
                            35,  # session_ticket
                            49,  # post_handshake_auth
                            52):  # transparency_info
                ext = TLSExtension().create(ext_id, bytearray())
            else:
                raise ValueError("No autohandler for extension {0}"
                                 .format(ExtensionType.toStr(ext_id)))
            extensions.append(ext)
        # print(extension)
        return extensions

    def generateClientHello(self):
        self.session = None
        session_id = getRandomBytes(32)
        # session_id = bytearray()
        # session_id = getRandomBytes(16)
        client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
        self._clientRandom=client_random
        clientHello = ClientHello()
        clientHello.create((3,2),
                           client_random,
                           session_id,
                           self.ciphersuites,
                           extensions=self.generate_extensions())
        self.CH = clientHello
        # print(clientHello)
        
        return clientHello
    def generateClientKeyExchange(self):
        if self.CH == None or self.SH == None:
            # print("SSSSS")
            self.ciphersuites = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
            CH = ClientHello()
            session_id = getRandomBytes(32)
            client_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
            CH.create((3,3),
                        client_random,
                        session_id,
                        self.ciphersuites,
                        extensions=self.generate_extensions()) 
            
            
            SH = ServerHello()
            server_random=bytes.fromhex(str(hex(int(time.time())))[2:])+os.urandom(28)
            SH.create((3,3),
                          server_random,
                          session_id,
                          self.ciphersuites[0])
            
            keyExchange = RSAKeyExchange(self._cipherSuite, CH,
                                             SH, None)

            if self.SC == None:
                server_cert = open('./key/server.cer', 'rb').read()
                server_cert = str(server_cert, 'utf-8')
                server_cert_chain = X509CertChain()
                server_cert_chain.parsePemList(server_cert)
                keyExchange.cipherSuite=self.ciphersuites[0]
                keyExchange.version = (3,3)


            self.premasterSecret = keyExchange.processServerKeyExchange(server_cert_chain.getEndEntityPublicKey(),
                                                                    self.SKE)
                                                                    
        else:
            # print("else")
            # print(self._cipherSuite,CipherSuite.ecdheEcdsaSuites)
            if self._cipherSuite in CipherSuite.dhAllSuites:
                # print("1")
            
                keyExchange = DHE_RSAKeyExchange(self._cipherSuite, self.CH,
                                                self.SH, None)
                self.premasterSecret = keyExchange.processServerKeyExchange(self.SC.cert_chain.getEndEntityPublicKey(),
                                                                   self.SKE)

            
            elif self._cipherSuite in CipherSuite.ecdhAllSuites or self._cipherSuite in CipherSuite.ecdheEcdsaSuites:
                # print("2")

                keyExchange = ECDHE_RSAKeyExchange(self._cipherSuite, self.CH,
                                                self.SH, None,
                                                [self.ecdhCurve])
                self.premasterSecret = keyExchange.processServerKeyExchange(self.SC.cert_chain.getEndEntityPublicKey(),
                                                                   self.SKE)

            else:
                # print("3")
                keyExchange = RSAKeyExchange(self._cipherSuite, self.CH,
                                                self.SH, None)
                self.premasterSecret = keyExchange.processServerKeyExchange(self.SC.cert_chain.getEndEntityPublicKey(),
                                                                   self.SKE)
        clientKeyExchange = keyExchange.makeClientKeyExchange()
        return clientKeyExchange
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
        self._certificate_verify_handshake_hash = self._handshake_hash.copy()

        valid_sig_algs = self._sigHashesToList(self.settings, self.privateKey,
                                                   self.cert_chain)
        if self.CR==None:
            # valid_sig_algs=[(8, 6), (8, 5), (8, 4), (6, 1), (5, 1), (4, 1), (3, 1), (2, 1)]
            self.CR=CertificateRequest(version=(3,0)).create()
            # print(self.CR.supported_signature_algs)
            # print(valid_sig_algs)
            self.CR.supported_signature_algs=[(4, 3), (5, 3), (6, 3), (8, 7), (8, 8), (8, 9), (8, 10), (8, 11), (8, 4), (8, 5), (8, 6), (4, 1), (5, 1), (6, 1), (3, 3), (2, 3), (3, 1), (2, 1), (3, 2), (2, 2), (4, 2), (5, 2), (6, 2)]
        certificateVerify = KeyExchange.makeCertificateVerify(
                    self.version,
                    self._certificate_verify_handshake_hash,
                    valid_sig_algs,
                    self.privateKey,
                    self.CR,
                    self.premasterSecret,
                    self._clientRandom,
                    self._serverRandom)
        return certificateVerify
    
    def changestate(self):
        # print(self.premasterSecret)
        # print(self._clientRandom)
        if len(self.premasterSecret) != 0 and len(self._clientRandom) !=0:
            self.masterSecret = calc_key(self.version, self.premasterSecret,
                                        self._cipherSuite, b"master secret",
                                        client_random=self._clientRandom,
                                        server_random=self._serverRandom,
                                        output_length=48)
        else:
            self.masterSecret = bytearray(b'')
            if self.SH == None:
                self._cipherSuite = self.ciphersuites[0]
        # print("MasterKey",self.masterSecret)
        # print(self._cipherSuite)
        label = b"client finished"
        # print(self._handshake_hash)
        verifyData = calc_key(self.version, self.masterSecret,
                              self._cipherSuite, label,
                              handshake_hashes=self._handshake_hash,
                              output_length=12)
        self.client_verify_data=verifyData

        # print("verifydata",verifyData)
        # print (self._cipherSuite, self.masterSecret, self._clientRandom,self._serverRandom)
        # if self._cipherSuite == None:
        #     self._cipherSuite = 49171
        # self._cipherSuite == 49171
        # print(self._cipherSuite)
        self._calcPendingStates(self._cipherSuite, self.masterSecret, 
                                self._clientRandom,self._serverRandom, 
                                ['python'])
        self._changeWriteState()


    def generateClientFinished(self):
        # self.changestate()
        client_finished = Finished(self.version).create(self.client_verify_data)
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
        # appdata = ApplicationData().create(b"GET / HTTP/1.1\r\nHost: testserver.com\r\n\r\n")
        appdata = ApplicationData().create(b"GET / HTTP/1.0\n\n") # for openssl
        return appdata
    
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
                            AlertDescription.illegal_parameter,
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
        
    def process_recieve(self):
        time.sleep(0.3)
        
        receive_msg = ''
        while True:
            try:
                for result in self._getMsg(ContentType.all, HandshakeType.all):
                    pass
            except Exception as e:
                break
            # print(result)
            recordHeader, p = result
            if recordHeader.type == ContentType.change_cipher_spec:
                ccs = ChangeCipherSpec().parse(p)
                receive_msg += '-ChangeCipherSpec'
                self._changeReadState()
            if recordHeader.type == ContentType.application_data:
                appdata = ApplicationData().parse(p)
                receive_msg += '-AppliciationData'
            if recordHeader.type == ContentType.alert:
                alert = Alert().parse(p)
                receive_msg += '-' + alert.descriptionName
            if recordHeader.type == ContentType.handshake:
                subType = p.get(1)
                self._handshake_hash.update(p.bytes)
                if subType == HandshakeType.client_hello:
                    receive_msg += '-ClientHello'
           
                if subType == HandshakeType.server_hello:

                    serverHello = ServerHello().parse(p)
                    self.SH = serverHello
                    self._serverRandom = serverHello.random
                    # print(self.SH.cipher_suite)
                    self._cipherSuite = serverHello.cipher_suite
                    receive_msg += '-ServerHello'
                if subType == HandshakeType.certificate_request:
                    self.CR = CertificateRequest(self.version).parse(p)
                    receive_msg += '-CertificateRequest'                
                if subType == HandshakeType.certificate:
                    self.SC = Certificate(CertificateType.x509, self.version).parse(p)
                    # self.SC = Certificate(self.SH.certificate_type, self.version).parse(p)
                    receive_msg += '-Certificate'
                
                if subType == HandshakeType.certificate_verify:
                    certificate_verify = CertificateVerify(self.version).parse(p)
                    receive_msg += '-CertificateVerify'
                if subType == HandshakeType.server_key_exchange:
                    print(self._cipherSuite,ContentType.handshake)
                    # self._cipherSuite
                    serverKeyExchange=ServerKeyExchange(
                                            cipherSuite=self._cipherSuite, version=self.version).parse(p)
                    # serverKeyExchange=ServerKeyExchange(HandshakeType.server_key_exchange,
                    #                         self.version).parse(p)
                    
                    self.SKE=serverKeyExchange
                    receive_msg += '-serverKeyExchange'
                    if self.version >= (3, 3) \
                            and (self._cipherSuite in CipherSuite.certAllSuites or
                                    self._cipherSuite in CipherSuite.ecdheEcdsaSuites) \
                            and self._cipherSuite not in CipherSuite.certSuites:
                        self.serverSigAlg = (serverKeyExchange.hashAlg,
                                    serverKeyExchange.signAlg)
                    if self._cipherSuite in CipherSuite.dhAllSuites:
                        self.dhGroupSize = numBits(serverKeyExchange.dh_p)
                    if self._cipherSuite in CipherSuite.ecdhAllSuites:
                        self.ecdhCurve = serverKeyExchange.named_curve

                if subType == HandshakeType.server_hello_done:
                    receive_msg += '-ServerHelloDone'

                if subType == HandshakeType.finished:
                    receive_msg += '-Finished'
     
                    
                if subType == HandshakeType.new_session_ticket:
                    newSessionTicket = NewSessionTicket().parse(p)
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





