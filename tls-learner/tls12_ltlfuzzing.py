from TLSMapper.TLS12SUT import *
from fuzzing.LTLfFuzzer import *
from aalpy.utils import visualize_automaton
from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWMethodEqOracle, StatePrefixEqOracle

ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
              CipherSuite.TLS_AES_256_GCM_SHA384,
              CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
              CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]

# openssl
# # /usr/local/openssl/bin/
command = ['openssl', 's_server', '-cert', '/root/Desktop/modelLearing/tls_fucker/key/server.cer', '-key', '/root/Desktop/modelLearing/tls_fucker/key/deserver.key', '-CAfile', '/root/Desktop/modelLearing/tls_fucker/key/ca.cer', '-keylogfile', '/root/Desktop/modelLearing/tls_fucker/key/key.log', '-HTTP']
command = None
sul = TLS12SUT(keyfile='./key/declient.key', certfile='./key/client.cer', ciphersuites=ciphersuites, target_cmd=command)
sul.target_ip = '127.0.0.1'
sul.target_port = 4433

# # wolfssl
# command = ['/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/examples/server/server', '-v', '4', '-p', '4433', '-x', '-g', '-i']

# sul = TLS12SUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)

# sul = TLS12SUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)

# alphabet = ['ClientHello', 'ChangeCipherSpec', 'Certificate', 'CertificateVerify', 'Finish', 'ApplicationData', 'ClosureAlert', 'ErrorAlert', 'CertificateRequest']

# # for test

alphabet = ['ClientHello', 'ClientKeyExchange','ChangeCipherSpec','Finish','ApplicationData','Certificate','CertificateVerify', 'ClosureAlert', 'ErrorAlert']

# alphabet = ['ClientHelloRSA','Certificate', 'ClientKeyExchange','CertificateVerify','ChangeCipherSpec','Finish', 'ApplicationData']
# alphabet = ['Certificate', 'ClientHelloRSA', 'ClientKeyExchange', 'ChangeCipherSpec']

# alphabet = ['ClientHelloRSA', 'ClientKeyExchange','ChangeCipherSpec','Finish', 'ApplicationData']
# alphabet = ['ClientHelloRSA', 'ClientHelloRSA']


sul.query(alphabet)

# # for model learning
eq_oracle = RandomWMethodEqOracle(alphabet, sul)
eq_oracle = StatePrefixEqOracle(alphabet, sul,walks_per_state=10, walk_len=6)
#
model = run_Lstar(alphabet, sul, eq_oracle, 'mealy', cache_and_non_det_check=False)
model.save(file_path='test_tls12')
# visualize_automaton(model)



