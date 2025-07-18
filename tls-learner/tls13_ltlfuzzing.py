from TLSMapper.TLSSUT import *
from fuzzing.LTLfFuzzer import *
from aalpy.utils import visualize_automaton
from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWMethodEqOracle, StatePrefixEqOracle

ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
              CipherSuite.TLS_AES_256_GCM_SHA384,
              CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]

# openssl s_server -cert /home/ju/Desktop/tls_fucker/key/server.cer -key /home/ju/Desktop/tls_fucker/key/deserver.key -CAfile /home/ju/Desktop/tls_fucker/key/ca.cer -keylogfile /home/ju/Desktop/tls_fucker/key/key.log -HTTP

# openssl s_server -cert /home/ju/Desktop/tls_fucker/key/server.cer -key /home/ju/Desktop/tls_fucker/key/deserver.key -CAfile /home/ju/Desktop/tls_fucker/key/ca.cer  -HTTP
# openssl s_server -cert key/server.cer -key key/deserver.key -CAfile /home/ju/Desktop/tls_fucker/key/ca.cer  -HTTP

# openssl
# /usr/local/openssl/bin/
# command = ['openssl', 's_server', '-cert', '/home/zdl/openssl_test/server.crt', '-key', '/home/zdl/openssl_test/server.key', '-Verify', '1', '-CAfile', '/home/zdl/openssl_test/ca.crt', '-keylogfile', '/home/zdl/openssl_test/key.log', '-HTTP']
# sul = TLS13SUT(keyfile='./TLSMapper/key/client.key', certfile='./TLSMapper/key/client.crt', ciphersuites=ciphersuites, target_cmd=command)

# sul = TLS13SUT(keyfile='./TLSMapper/key/declient.key', certfile='./TLSMapper/key/client.cer', ciphersuites=ciphersuites, target_cmd=None)


# wolfssl
# command = ['/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/examples/server/server', '-v', '4', '-p', '4433', '-x', '-g', '-i']
command = None
# /home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem


sul = TLS13SUT(keyfile='./TLSMapper/key/declient.key', certfile='./TLSMapper/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)
sul.target_ip = '127.0.0.1'
sul.target_port = 4433


# sul = TLS13SUT(keyfile='./TLSMapper/key/declient.key', certfile='./TLSMapper/key/client.cer', ciphersuites=ciphersuites, target_cmd=None)



# sul = TLS13SUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)

# sul = TLS13SUT(keyfile='/home/kai/Desktop/wolfssl-5.6.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/wolfssl-5.6.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)


# alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData',  "ResumptionClientHello", 'ClosureAlert', 'ErrorAlert', 'CertificateRequest', 'Certificate', 'CertificateVerify']

# alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData', 'Certificate', 'CertificateVerify', 'ClosureAlert', 'ErrorAlert', 'CertificateRequest']


# alphabet = ['ClientHello',  'ChangeCipherSpec','Certificate', 'ChangeCipherSpec','ChangeCipherSpec','CertificateVerify', 'ChangeCipherSpec','Finish', 'ApplicationData']

# alphabet = ['ClientHello', 'Certificate', 'CertificateVerify', 'Finish', 'ApplicationData']
# alphabet = ['ClientHello', 'Certificate', 'Finish', 'ApplicationData']
# alphabet = ['ClientHello', 'Certificate', 'Finish']
# alphabet = ['ClientHello', 'ChangeCipherSpec', 'Certificate', 'CertificateVerify', 'Finish', 'ApplicationData', "ResumptionClientHello"]
# alphabet = ['ClientHello', 'ChangeCipherSpec', 'ChangeCipherSpec', 'Finish', 'ApplicationData']
# alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', "KeyUpdate", 'ApplicationData', "KeyUpdate", 'ApplicationData']
alphabet = ['ClientHello', 'ChangeCipherSpec', 'Certificate',  'CertificateVerify', 'Finish', 'ApplicationData','ResumptionClientHello', 'KeyUpdate']

# alphabet=['ClientHello', 'Certificate', 'CertificateVerify', 'Finish', 'ResumptionClientHello', 'Finish', 'KeyUpdate', 'ResumptionClientHello', 'ResumptionClientHello']
# alphabet=['ClientHello', 'Certificate', 'CertificateVerify', 'Finish', 'KeyUpdate', 'ResumptionClientHello', 'ResumptionClientHello', 'Finish']
# alphabet=['Finish']
# alphabet=['ClientHello', 'Certificate', 'CertificateVerify', 'Finish', 'ResumptionClientHello', 'Finish', 'ResumptionClientHello', 'Finish', 'ResumptionClientHello', 'ResumptionClientHello']


# alphabet = ['ClientHelloEmtyKeyShare', 'ClientHello', 'ChangeCipherSpec', 'Certificate',  'CertificateVerify', 'Finish', 'KeyUpdate', 'ApplicationData']

# , 'ApplicationData', "KeyUpdate", 'ApplicationData'

# sul.query(alphabet)
# alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData']
sul.query(alphabet)
# for model learning
eq_oracle = RandomWMethodEqOracle(alphabet, sul)
# # # # eq_oracle = StatePrefixEqOracle(alphabet, sul,walks_per_state=10, walk_len=6)

model = run_Lstar(alphabet, sul, eq_oracle, 'mealy', cache_and_non_det_check=False)
# model.save(file_path='tls13_ju')
model.save(file_path='results/openssl/openssl-111f/openssl-111f-tls13')
visualize_automaton(model)



# fuzzer = LTLfFuzzer(TLS13_formulas, alphabet, sul, out_dir='test_tls', resume=True)
# fuzzer.fuzzing(86400)
# fuzzer.replay('test_tls/formula_2/seed-1')

# for k, v in TLS13_formulas.items():
#     ltl_formula_to_dfa(k, v)



