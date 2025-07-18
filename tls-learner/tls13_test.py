from TLSMapper.TLSTEST import *


ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
              CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]

def test_happy_flow():
    ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
    alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData']
    command = None
    # command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='/home/kai/Desktop/123/tls_infer/key/declient.key', certfile='/home/kai/Desktop/123/tls_infer/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)
    sul.use_psk = False
    sul.query(alphabet)

def test_happy_flow_with_cert():
    ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
    alphabet = ['ClientHello', 'ChangeCipherSpec', 'Certificate',  'CertificateVerify', 'Finish', 'ApplicationData']
    command = None
    # command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='/home/kai/Desktop/123/tls_infer/key/declient.key', certfile='/home/kai/Desktop/123/tls_infer/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)


def test_happy_flow_with_cert_wolfssl():
    ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
    alphabet = ['ClientHello',  'Certificate',  'CertificateVerify', 'Finish', 'ApplicationData']
    command = None
    # command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)


def test_happy_flow_with_PSK():
    ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
    psk_ident=b'Client_identity'
    psk=b'\x12\x34\x56'
    psk_hash='sha256'
    alphabet = ['ClientHello',  'ChangeCipherSpec', 'Finish', 'ApplicationData']
    command = None
    # command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    # sul = TLSTESTSUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)
    sul = TLSTESTSUT(keyfile='/home/kai/Desktop/123/tls_infer/key/declient.key', certfile='/home/kai/Desktop/123/tls_infer/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)

    sul.use_psk = True
    sul.pskConfigs = [(psk_ident, psk, psk_hash)]
    sul.query(alphabet)




# test_happy_flow()

def test_cipher_suit():
    '''
    The algorithms are all encrypted with relevant data authentication (AEAD) algorithms
    error: no shared cipher
    recieve: Alert.handshake_failure
    '''
    ciphersuites = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    alphabet = ['ClientHello']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/declient.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)

# test_cipher_suit()

def test_group_curve():
    '''
    If the client does not provide enough "key_share" extension
    test: GroupName.secp224r1
        error: final_key_share:no suitable key share 
        recieve: Alert.handshake_failure
    test: GroupName.secp256r1
        recieve: ServerHello-ChangeCipherSpec-EncryptedExtensions-Certificate-CertificateVerify-Finished
    if no key_share
        recieve: Alert.missing_extension
    if not consistent
        recieve: Alert.illegal_parameter
        
    '''
 
    alphabet = ['ClientHello']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/declient.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    sul.pre_ext = [None,[GroupName.secp224r1],None]
    sul.query(alphabet)
    sul.pre_ext = [None,[GroupName.secp256r1],None]
    sul.query(alphabet)

# test_group_curve()


def test_double_client_hello():
    '''
    If the client does not provide enough "key_share" extension
    test: enc_client_hello
    recieve: unexpected_message
        
    '''
 
    alphabet = ['ClientHello','ClientHello']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/client.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)

# test_double_client_hello()



def test_compress_method():
    '''
    For each TLS 1.3 ClientHello, this vector must contain one byte, 
    set to zero, corresponding to the "null" compression method in previous versions of TLS. 
    If a TLS 1.3 ClientHello containing any other values in this field is received, 
    the server must use the "illegal_parameter" alert to terminate the handshake
    test: compression method <> null
    if method is unknown
    recieve: decode_error
    ps: change message.py 
        
    '''
 
    alphabet = ['ClientHello']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/client.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)

# test_compress_method()

def test_version():
    '''
    error: routines:tls_early_post_process_client_hello:unsupported protocol
    recieve: protocol_version
        
    '''
 
    alphabet = ['ClientHello']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/client.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    sul.pre_ext = [[(3, 3)],[GroupName.secp256r1],None]
    sul.query(alphabet)
    
# test_version()

def test_signature_algorithms():
    '''
    other
    routines:tls_choose_sigalg:no suitable signature algorithm
    recieve: handshake_failure

    empty
    missing_extension
    
    if missing signature_algorithms_cert
    it doesnot matter
    '''

    print(RSA_SIG_ALL)
 
    alphabet = ['ClientHello']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/client.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)
    # sul.pre_ext = [None,None,[(6,1)]]
    # sul.query(alphabet)

# test_signature_algorithms()


def test_post_handshake_auth():
    '''
    set mytls13.py ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
    it doesnot matter
    '''

    print(RSA_SIG_ALL)
 
    alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/client.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)
    # sul.pre_ext = [None,None,[(6,1)]]
    # sul.query(alphabet)
# test_post_handshake_auth()

def test_client_hello_first():
    '''
    当客户端首次连接到服务器时，必须将ClientHello作为其第一个TLS消息发送。
    it doesnot matter
    '''

    
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/client.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    alphabet = ['ClientHello', 'ChangeCipherSpec']
    sul.query(alphabet)
    alphabet = [ 'ChangeCipherSpec', 'ClientHello']
    sul.query(alphabet)
    alphabet = ['Certificate', 'ChangeCipherSpec']
    sul.query(alphabet)
    alphabet = ['ApplicationData', 'ChangeCipherSpec']
    sul.query(alphabet)
   
# test_client_hello_first()
# test_happy_flow()
'''

for mutal handshake

'''

def test_resumption():
    ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
    alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData','TLS13ReClientHello']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='./key/client.key', certfile='./key/client.crt', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)


def test_resumption_with_cert():
    ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
    # alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData','TLS13ReClientHello']
    alphabet = ['ClientHello', 'ChangeCipherSpec', 'Certificate',  'CertificateVerify', 'Finish','ResumptionClientHello', 'Finish', 'ApplicationData']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='/home/kai/Desktop/123/tls_infer/key/declient.key', certfile='/home/kai/Desktop/123/tls_infer/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)

def test_hrr():
    ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
    # alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData','TLS13ReClientHello']
    alphabet = ['ClientHelloEmtyKeyShare','ClientHello']
    command = ['openssl', 's_server', '-cert', './key/server.crt', '-key', './key/server.key', '-Verify', '1', '-CAfile', './key/ca.crt', '-keylogfile', './key/key.log', '-HTTP']
    sul = TLSTESTSUT(keyfile='/home/kai/Desktop/123/tls_infer/key/declient.key', certfile='/home/kai/Desktop/123/tls_infer/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)
    sul.query(alphabet)




# test_resumption_with_cert()
# test_happy_flow()
# test_happy_flow_with_cert()
# test_happy_flow_with_cert_wolfssl()
# test_happy_flow_with_PSK()
test_hrr()