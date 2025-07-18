import utils
import os
import subprocess
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

# sul = TLS12SUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites,  target_cmd=command)

alphabet = ['ClientHello', 'ChangeCipherSpec', 'Certificate', 'CertificateVerify', 'Finish', 'ApplicationData', 'ClosureAlert', 'ErrorAlert', 'CertificateRequest']

# # for test

# alphabet = ['ClientHello']
# alphabet = ['ApplicationData'] 

# alphabet_plus = ["NoClientCert",'TLS13ReClientHello','ClientHelloEmtyKeyShare','KeyUpdate','ResumptionClientHello']


# alphabet = alphabet + alphabet_plus

# alphabet = ['ClientHelloRSA','Certificate', 'ClientKeyExchange','CertificateVerify','ChangeCipherSpec','Finish', 'ApplicationData']
# alphabet = ['Certificate', 'ClientHelloRSA', 'ClientKeyExchange', 'ChangeCipherSpec']

# alphabet = ['ClientHelloRSA', 'ClientKeyExchange','ChangeCipherSpec','Finish', 'ApplicationData']
# alphabet = ['ClientHelloRSA', 'ClientHelloRSA']


# sul.query(alphabet)



pname = 'openssl'
pid = utils.get_pid(pname)
print(f"pid:{pid}")
start_address, end_address = utils.get_heap_address_range(pid)
size = end_address - start_address
if start_address is None or end_address is None:
    print("cann't get heap address!")
    exit(1)





# 本地路径
mem_path = f"/proc/{pid}/mem"
tmp_file = 'tmp.bin'

# 创建命令来读取内存数据
heap_size = end_address - start_address
command = [
    "dd", 
    f"if={mem_path}", 
    f"bs=1", 
    f"skip={start_address}", 
    f"count={heap_size}", 
    f"of={tmp_file}"
]
print('prerun')
# 执行命令并捕获输出
result = subprocess.run(command, capture_output=True, text=True)

if result.returncode != 0:
    error = result.stderr.strip()
    print(error)
    if 'cannot skip to specified offset' not in error:
        print('error')
        exit()


        
print(f"成功将本地进程 {pid} 的堆内存保存到文件 {tmp_file}")

with open(tmp_file,'rb') as f:
    heap_memory = f.read()
# os.remove(tmp_file)
img = utils.bin2img(heap_memory)
img.save('1.png')