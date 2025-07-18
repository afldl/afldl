from TLSMapper.TLS11SUT import *
from fuzzing.LTLfFuzzer import *
from aalpy.utils import visualize_automaton
from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWMethodEqOracle, StatePrefixEqOracle

# ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
#               CipherSuite.TLS_AES_256_GCM_SHA384,
#               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]

ciphersuites=[CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
              CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
              ]
# ,
#               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]

# openssl
# # /usr/local/openssl/bin/
command = ['openssl', 's_server', '-cert', '/home/zdl/openssl_test/server.crt', '-key', '/home/zdl/openssl_test/server.key', '-Verify', '1', '-CAfile', '/home/zdl/openssl_test/ca.crt', '-keylogfile', '/home/zdl/openssl_test/key.log', '-HTTP']

# sul = TLS12SUT(keyfile='./TLSMapper/key/declient.key', certfile='./TLSMapper/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)
sul = TLS11SUT(keyfile='./TLSMapper/key/declient.key', certfile='./TLSMapper/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)


# wolfssl
# command = ['/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/examples/server/server', '-v', '4', '-p', '4433', '-x', '-g', '-i']

# sul = TLS12SUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)




# alphabet = ['ClientHello','Certificate', 'ClientKeyExchange','CertificateVerify','ChangeCipherSpec','Finish','ApplicationData', 'ClosureAlert', 'ErrorAlert', 'CertificateRequest']

# alphabet = ['ClientHello', 'ClientKeyExchange','ChangeCipherSpec','Finish','ApplicationData','Certificate','CertificateVerify', 'ClosureAlert', 'ErrorAlert', 'CertificateRequest']


alphabet = ['ClientHello', 'ClientKeyExchange', 'ChangeCipherSpec','Finish','ApplicationData']


sul.query(alphabet)

# # for model learning
# eq_oracle = RandomWMethodEqOracle(alphabet, sul)
# # eq_oracle = StatePrefixEqOracle(alphabet, sul,walks_per_state=10, walk_len=6)

# model = run_Lstar(alphabet, sul, eq_oracle, 'mealy', cache_and_non_det_check=False)
# model.save(file_path='test_tls')
# visualize_automaton(model)




