import os
import sys
import networkx as nx
import utils
import logging
from scapy.all import AsyncSniffer, wrpcap  # 新增Scapy相关引用

from TLSMapper.TLSSUT import *
from fuzzing.LTLfFuzzer import *
from aalpy.utils import visualize_automaton
from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWMethodEqOracle, StatePrefixEqOracle
from TLSMapper.TLS12SUT import *
import os
from scapy.all import sniff, TCP, Raw, IP
from scapy.utils import PcapReader

from itertools import groupby

def check_consecutive_elements(lst):
    for _, group in groupby(lst):
        if len(list(group)) >= 4:  # 如果某个元素连续出现了4次或更多
            return False
    return True


def remove_duplicates(packets):
    seen = set()  # 用于存储已经遇到的序列号
    result = []  # 用于存储去重后的数据包
    
    for packet in packets:
        # 假设我们根据TCP序列号去重，需要根据实际情况调整
        # 注意：并非所有数据包都有TCP层，因此需要进行检查
        if packet.haslayer('TCP'):
            seq_num = packet['TCP'].seq
            if seq_num not in seen:
                seen.add(seq_num)
                result.append(packet)
        else:
            # 对于没有TCP层的数据包，直接添加到结果中
            result.append(packet)
    
    return result

def pcap_to_raw(input_dir, output_dir, direction_filter):
    """
    处理PCAP文件，提取指定方向的TCP应用层数据并保存为RAW文件
    
    参数：
    input_dir (str)    - 包含PCAP文件的输入目录
    output_dir (str)   - 输出RAW文件的目录
    direction_filter (str) - BPF过滤规则，默认捕获发往80端口的数据
    """
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 遍历所有PCAP文件
    for filename in sorted(os.listdir(input_dir)):
        if not filename.lower().endswith(('.pcap', '.pcapng')):
            continue
            
        input_path = os.path.join(input_dir, filename)
        output_path = os.path.join(output_dir, 
                                 os.path.splitext(filename)[0] + ".raw")


        # 读取并过滤数据包
        packets = sniff(offline=input_path,
                       filter=f"{direction_filter}")
                # 去重并转换为列表
        unique_packets = remove_duplicates(packets)

        # 如果你需要将结果转换成普通列表，可以简单地这样做：
        unique_packets_list = list(unique_packets)
        packets = unique_packets_list
        print(len(packets))
          
        # 提取应用层数据
        raw_payload = b""
        for pkt in packets:
            if pkt.haslayer(Raw):
                raw_payload += bytes(pkt[Raw].load)

        # 写入RAW文件
        if raw_payload:
            with open(output_path, 'wb') as f:
                f.write(raw_payload)
            print(f"Processed {filename} => {output_path} ({len(raw_payload)} bytes)")
        else:
            print(f"No valid data in {filename}")

if __name__ == "__main__":

    out_dir = 'results/openssl/openssl-111f/openssl-111f-tls12'
    os.makedirs(out_dir,exist_ok=True)

    dot_file = "results/openssl/openssl-111f/openssl-111f-tls12.dot"
    start_node = "s0"
    graph = nx.DiGraph(nx.nx_pydot.read_dot(dot_file))
    nodes = list(graph.nodes())
    nodes.remove('__start0')
    print(nodes)
    nodes.remove('s0')

    ciphersuites=[CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]

    command = None
    sul = TLS12SUT(
        keyfile='./TLSMapper/key/declient.key',
        certfile='./TLSMapper/key/client.cer',
        ciphersuites=ciphersuites,
        target_cmd=command
    )
    sul.target_ip = '127.0.0.1'
    sul.target_port = 4433

    # alphabet = ['ClientHello', 'ChangeCipherSpec', 'Finish', 'ApplicationData']
    # sul.query(alphabet)

    pcap_dir = f"{out_dir}/pcap"
    raw_dir = f"{out_dir}/raw"
    alphabet_dir = f"{out_dir}/alphabet"

    os.makedirs(pcap_dir,exist_ok=True)
    os.makedirs(raw_dir,exist_ok=True)
    os.makedirs(alphabet_dir,exist_ok=True)

    max_len = 20
    node_paths = {}
    max_path = 10
    for target_node in nodes:


        # 生成测试路径
        paths = utils.generate_unique_paths(graph, start_node, target_node,max_path, max_len)
        paths = [item for item in paths if check_consecutive_elements(item['nodes'])]
        print(f"len:{len(paths)}")
        for idx,path in enumerate(paths): 
            inputs, outputs = utils.get_io(path)
            if 'SendFailed' in outputs:
                continue
            nodes = path['nodes']

            pcap_path = f"{pcap_dir}/{target_node}_{idx}.pcap"  # PCAP文件名
            txt_path = f"{alphabet_dir}/{target_node}_{idx}.txt"    # 输入日志文件名
            
            combined_list = [f"{x} {y}" for x, y in zip(inputs, nodes)]
            # 保存输入字母到文本文件
            with open(txt_path, 'w') as f:
                f.write("\n".join(combined_list))
            
            # 设置抓包过滤器
            bpf_filter = f"host {sul.target_ip} and port {sul.target_port}"
            # 基于 TCP 协议的 TLS 特征修改过滤器
            bpf_filter = f"tcp and host {sul.target_ip} and port {sul.target_port} and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16 or tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x17 or tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x14 or tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x15) "  # 直接检查 TLS 握手协议位置
                
            # 开始抓包
            sniffer = AsyncSniffer(
                filter=bpf_filter,
                iface="lo",
                store=True
            )
            sniffer.start()
            
            # 执行测试
            response = sul.query(inputs)
            
            # 停止抓包并保存
            sniffer.stop()
            wrpcap(pcap_path, sniffer.results)
            
            # 结果验证
            if response != outputs and outputs != []:
                logging.error(f"响应与预期不符 节点：{target_node}")
                logging.error(f"预期输出：{outputs}")
                logging.error(f"实际响应：{response}")
                sys.exit(1)

            # 成功日志
            logging.info(f"节点 {target_node} 测试完成，抓包已保存至 {pcap_path}")

    # 最终验证通过提示
    logging.info("所有节点测试通过！")




    pcap_to_raw(
        input_dir=pcap_dir,
        output_dir=raw_dir,
        direction_filter="tcp dst port 4433"
    )

    logging.info("所有节点测试通过！")
