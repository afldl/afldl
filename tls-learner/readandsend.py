from scapy.all import rdpcap, IP, TCP, send
import time
# 读取PCAP文件
input_path = 'in-tls/pcap/s1.pcap'  # 替换为你的PCAP文件路径
packets = rdpcap(input_path)
# packets = packets[0]
packet = packets[0]

print(packet)
app_data = packet['Raw'].load
print(app_data.hex())
print(type(app_data.hex()))
print(app_data)


# for packet in packets:
#     if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer('Raw'):
#         # 提取IP和TCP层信息以及应用层数据
#         ip_layer = IP(dst="127.0.0.1")  # 修改目标IP地址
#         tcp_layer = TCP(dport=4433, sport=packet[TCP].sport, seq=packet[TCP].seq, ack=packet[TCP].ack, flags='PA')  # 修改目标端口和其他TCP头部信息
#         app_data = packet['Raw'].load  # 应用层数据
#         print(app_data)
        
#         # 构建新的数据包
#         new_packet = ip_layer/tcp_layer/app_data
        
#         try:
#             # 发送新构建的数据包
#             send(new_packet)
#             print("Packet sent.")


#         except Exception as e:
#             print(f"An error occurred while sending the packet: {e}")
        
#         time.sleep(1)