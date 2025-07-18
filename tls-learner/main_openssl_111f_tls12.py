import os
import sys
import networkx as nx
import utils
import logging
out_dir = 'results/openssl/openssl-111f/openssl-111f-tls12-mem'

# 示例：解析 graph.dot 文件，查找从 s0 到 s1 的最短路径
dot_file = "dots/openssl-111f-tls12.dot"
start_node = "s0"
graph = nx.DiGraph(nx.nx_pydot.read_dot(dot_file))
nodes = list(graph.nodes())
nodes.remove('__start0')
print(nodes)
# nodes.remove('s0')


from TLSMapper.TLS12SUT import *
from fuzzing.LTLfFuzzer import *
from aalpy.utils import visualize_automaton
from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWMethodEqOracle, StatePrefixEqOracle

ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
              CipherSuite.TLS_AES_256_GCM_SHA384,
              CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
              CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]


# /home/ubuntu/experiments/openssl/apps/openssl s_server -cert /home/ubuntu/experiments/key/server.cer -key /home/ubuntu/experiments/key/deserver.key -CAfile /home/ubuntu/experiments/key/ca.cer 
# openssl
# # /usr/local/openssl/bin/
command = ['/home/ubuntu/experiments/openssl/apps/openssl', 's_server', '-cert', '/home/ubuntu/experiments/key/server.cer', '-key', '/home/ubuntu/experiments/key/deserver.key', '-CAfile', '/home/ubuntu/experiments/key/ca.cer', '-keylogfile', '/home/ubuntu/experiments/key/key.log', '-HTTP']
# command = None
sul = TLS12SUT(keyfile='./TLSMapper/key/declient.key', certfile='./TLSMapper/key/client.cer', ciphersuites=ciphersuites, target_cmd=command)
sul.target_ip = '127.0.0.1'
sul.target_port = 4433

# # wolfssl
# command = ['/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/examples/server/server', '-v', '4', '-p', '4433', '-x', '-g', '-i']

# sul = TLS12SUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)

# sul = TLS12SUT(keyfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-key.pem', certfile='/home/kai/Desktop/ssl_server/wolfssl-4.5.0-stable/certs/client-cert.pem', ciphersuites=ciphersuites, target_cmd=command)

# alphabet = ['ClientHello', 'ChangeCipherSpec', 'Certificate', 'CertificateVerify', 'Finish', 'ApplicationData', 'ClosureAlert', 'ErrorAlert', 'CertificateRequest']

# # for test

alphabet = ['ClientHello', 'ClientKeyExchange','ChangeCipherSpec','Finish','ApplicationData','Certificate','CertificateVerify', 'ClosureAlert', 'ErrorAlert', 'CertificateRequest']

alphabet_plus = ["NoClientCert",'TLS13ReClientHello','ClientHelloEmtyKeyShare','KeyUpdate','ResumptionClientHello']


alphabet = alphabet + alphabet_plus
# alphabet = ['ClientHelloRSA','Certificate', 'ClientKeyExchange','CertificateVerify','ChangeCipherSpec','Finish', 'ApplicationData']
# alphabet = ['Certificate', 'ClientHelloRSA', 'ClientKeyExchange', 'ChangeCipherSpec']

# alphabet = ['ClientHelloRSA', 'ClientKeyExchange','ChangeCipherSpec','Finish', 'ApplicationData']
# alphabet = ['ClientHelloRSA', 'ClientHelloRSA']


# sul.query(alphabet)






# per_state_samples = 1000
# max_len = 10
# for target_node in nodes:
#     all_paths = utils.generate_unique_paths(graph, start_node, target_node,per_state_samples, max_len)
#     print(f"generate {len(all_paths)} unique path")
#     all_paths.sort(key=lambda x: x['nodes'])
#     data_out_dir = os.path.join(out_dir,target_node)                    
#     if not os.path.exists(data_out_dir):
#         os.makedirs(data_out_dir)
#     for idx in range(0,len(all_paths)):
#         logging.info(f"node : {target_node}, index : {idx}")
#         data_out_path = os.path.join(data_out_dir,f"{target_node}_{idx}.png")
#         if os.path.exists(data_out_path):
#             continue
#         path = all_paths[idx]
#         inputs, outputs = utils.get_io(path)
#         # print(inputs)
#         # print(outputs)
#         response = sul.query(inputs)
#         # print(response)
#         if response != outputs and outputs != []:
#             logging.error("response != outputs!!!!")
#             exit(1)
#         # sul.fuzz_step(random.choice(alphabet))
#         utils.get_heap_mem_local('openssl',data_out_path)

per_state_samples = 100
max_len = 20
node_paths = {}
for target_node in nodes:
    paths = utils.generate_unique_paths(graph,start_node,target_node,per_state_samples,max_len)
    # paths = paths[:]
    print(f'generate {len(paths)} paths!')
    paths.sort(key=lambda x: x['nodes'])
    node_paths[target_node] = paths

for idx in range(0,per_state_samples):
    for target_node in nodes:
        data_out_dir = os.path.join(out_dir,target_node)
        if not os.path.exists(data_out_dir):
            os.makedirs(data_out_dir)

        data_out_path = os.path.join(data_out_dir,f"{target_node}_{idx}.png")
        if os.path.exists(data_out_path):
            continue
        # random_path = utils.generate_random_path(graph, start_node, target_node, max_len)
        path = random.choice(node_paths[target_node])
        inputs, outputs = utils.get_io(path)
        if 'SendFailed' in outputs:
            continue
        # print(inputs)
        # print(outputs)
        response = sul.query(inputs)
        # print(response)
        if response != outputs and outputs != []:
            logging.error("response != outputs!!!!")
            exit(1)
        
        utils.get_heap_mem_local('openssl',data_out_path)







