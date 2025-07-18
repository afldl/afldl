import random
import networkx as nx
import os
import subprocess
import struct
import paramiko
import logging
from PIL import Image


def bin2img(heap_memory):
    data = []
    addr = 0
    while addr < len(heap_memory):
        try:
            chunk_size,chunk_data = parse_chunk(heap_memory, addr)
            if chunk_size <= 32:
                data.append(chunk_data)
            addr += chunk_size
        except struct.error:
            print(f"[-] Failed to parse chunk at {hex(addr)}. Stopping.")
            break

    image = data2fig(data)
    return image


def data2fig(data):
    print(len(data))
    width, length = 74, 74
    total_pixels = width * length
    
    # 初始化一个空列表用于存储处理后的像素值
    pixel_data = []
    
    # 遍历输入的二进制数据列表，提取每个字节作为一个像素点
    for item in data:
        # 将每个数据项转换为bytearray以便于迭代
        byte_array = bytearray(item)
        # 添加到pixel_data中
        pixel_data.extend(byte_array)
        
        # 如果在处理过程中已经收集了足够的像素，则停止
        if len(pixel_data) >= total_pixels:
            break
    
    # 如果数据不足，则用0填充至所需的总像素数量
    if len(pixel_data) < total_pixels:
        pixel_data.extend([0] * (total_pixels - len(pixel_data)))
    
    # 确保我们只使用正好需要的像素数
    pixel_data = pixel_data[:total_pixels]
    
    # 创建一个新的300x300灰度图像
    img = Image.new('L', (width, length))
    
    # 将数据映射到图像中
    img.putdata(pixel_data)
    
    return img
    # return np.array(img)



def read_heap_memory_ssh(ssh, pid, start_address, end_address, output_file):
    try:

        # 远程路径
        remote_mem_path = f"/proc/{pid}/mem"
        remote_output_file = f"/home/1.bin"  # 临时文件存储在远程主机的 /tmp 目录
        tmp_output_file = '/home/1.png'
        
        # 创建命令来读取内存数据
        heap_size = end_address - start_address
        command = (
            f"dd if={remote_mem_path} bs=1 skip={start_address} count={heap_size} of={remote_output_file}"
        )
        # print(command)
        # 在远程主机执行命令
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout.channel.recv_exit_status()  # 等待命令执行完成
        
        # # 检查错误
        # error = stderr.read().decode()
        # if error and '无法跳至指定偏移量' not in error:
        #     logging.error(f"远程命令执行失败: {error}")
        #     return False
        
        # 将远程文件下载到本地
        sftp = ssh.open_sftp()
        sftp.get(remote_output_file, tmp_output_file)
        sftp.close()
        rm_command = (
            f"rm {remote_output_file}"
        )
        # print(rm_command)
        stdin, stdout, stderr = ssh.exec_command(rm_command)
        stdout.channel.recv_exit_status()  # 等待命令执行完成
        logging.info(f"成功将远程进程 {pid} 的堆内存保存到本地文件 {tmp_output_file}")
        with open(tmp_output_file,'rb') as f:
            heap_memory = f.read()
        
        img = bin2img(heap_memory)
        img.save(output_file)
        return True
    except Exception as e:
        logging.error(f"发生错误: {e}")
        return False

def get_heap_address_range_ssh(ssh, pid):
    try:
        # 远程路径
        remote_maps_path = f"/proc/{pid}/maps"
        
        # 创建命令来读取 /proc/<pid>/maps 文件
        command = f"cat {remote_maps_path}"
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout.channel.recv_exit_status()  # 等待命令执行完成
        
        # 解析输出
        for line in stdout:
            if "[heap]" in line:
                # 提取地址范围
                address_range = line.split(" ")[0]
                start_address, end_address = address_range.split("-")
                return int(start_address, 16), int(end_address, 16)
        
        logging.error("未找到堆地址范围。")
        return None, None
    except Exception as e:
        logging.error(f"发生错误: {e}")
        return None, None

def get_charon_pid_ssh(ssh):
    try:
        # 使用 pgrep 查找 charon 的 PID
        command = "pgrep charon"
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout.channel.recv_exit_status()  # 等待命令执行完成
        
        # 获取 PID 列表
        pids = stdout.read().decode().strip().split('\n')
        if pids:
            return int(pids[0])  # 返回第一个 PID
        else:
            logging.error("未找到 charon 进程。")
            return None
    except Exception as e:
        logging.error(f"获取 charon PID 时发生错误: {e}")
        return None

def ssh_connect(hostname, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)
        logging.error(f"成功连接到 {hostname}")
        return ssh
    except Exception as e:
        logging.error(f"SSH 连接失败: {e}")
        return None



def find_shortest_path(dot_file, start_node, target_node):
    # 解析 .dot 文件为有向图
    graph = nx.DiGraph(nx.nx_pydot.read_dot(dot_file))
    
    try:
        # 使用 networkx 的最短路径算法找到节点路径
        shortest_path = nx.shortest_path(graph, source=start_node, target=target_node)
        
        # 提取路径上的边数据
        path_edges = list(zip(shortest_path[:-1], shortest_path[1:]))  # 生成节点对的列表
        edge_data = [
            {
                "from": u,
                "to": v,
                "input": graph[u][v].get("label", "No label").split('/')[0][1:],  # 获取边的标签
                "output": graph[u][v].get("label", "No label").split('/')[1][:-1]  # 获取边的标签
            }
            for u, v in path_edges
        ]
        
        return {
            "nodes": shortest_path,  # 节点路径
            "edges": edge_data       # 边上的数据
        }
    except nx.NetworkXNoPath:
        return f"No path found from {start_node} to {target_node}."
    except nx.NodeNotFound as e:
        return str(e)

def generate_random_path(graph, src, dst, max_length):

    if src not in graph or dst not in graph:
        return f"Source node '{src}' or destination node '{dst}' not found in the graph."
    
    # 检查是否存在从 src 到 dst 的路径
    if not nx.has_path(graph, src, dst):
        return f"No path exists from {src} to {dst}."
    
    while True:  # 不断尝试生成路径，直到找到合法路径
        current_node = src
        path = [current_node]
        
        while current_node != dst or len(path) == 1:
            # 获取当前节点的所有邻居
            neighbors = list(graph.successors(current_node))
            
            # 如果没有邻居，无法继续前进
            if not neighbors:
                break  # 跳出内层循环，重新尝试生成路径
            
            # 随机选择一个邻居作为下一个节点
            next_node = random.choice(neighbors)
            path.append(next_node)
            
            # 更新当前节点
            current_node = next_node
            
            # 如果路径长度超过最大限制，重新尝试生成路径
            if len(path) > max_length:
                break  # 跳出内层循环，重新尝试生成路径
        
        # 如果找到合法路径（到达目标节点且未超过最大长度），则返回结果
        if current_node == dst and len(path) <= max_length:
            # 提取路径上的边数据
            path_edges = list(zip(path[:-1], path[1:]))
            edge_data = [
                {
                    "from": u,
                    "to": v,
                    "input": graph[u][v].get("label", "No label").split('/')[0][1:],  # 获取边的标签
                    "output": graph[u][v].get("label", "No label").split('/')[1][:-1]  # 获取边的标签
                }
                for u, v in path_edges
            ]
            
            return {
                "nodes": path,  # 节点路径
                "edges": edge_data  # 边上的数据
            }


def generate_random_path_from_dot(dot_file, src, dst, max_length):
    # 解析 .dot 文件为有向图
    graph = nx.DiGraph(nx.nx_pydot.read_dot(dot_file))
    return generate_random_path(graph,src, dst, max_length)

def get_heap_mem(ssh,output_file):
    # 获取远程 charon 进程的 PID
    pid = get_charon_pid_ssh(ssh)
    if not pid:
        # ssh.close()
        exit(1)
    
    # 获取堆地址范围
    start_address, end_address = get_heap_address_range_ssh(ssh, pid)
    if start_address is None or end_address is None:
        # ssh.close()
        exit(1)
    
    # print(f"远程堆地址范围: 0x{start_address:x}-0x{end_address:x}")
    
    # 保存堆内存到本地文件
    if read_heap_memory_ssh(ssh, pid, start_address, end_address, output_file):
        logging.info(f"堆内存已保存到本地文件: {output_file}")
    
    # 关闭 SSH 连接
    # ssh.close()

def get_io(path_dict):
    inputs, outputs = [], []
    for edge in path_dict['edges']:
        inputs.append(edge['input'])
        outputs.append(edge['output'])

    return inputs, outputs



# 解析 malloc_chunk 的函数
def parse_chunk(heap_memory, addr):
    # 解析 malloc_chunk 的 prev_size 和 size
    prev_size = struct.unpack("<Q", heap_memory[addr:addr+8])[0]
    size = struct.unpack("<Q", heap_memory[addr+8:addr+16])[0]
    
    # 检查标志位
    prev_inuse = size & 1
    is_mmapped = size & 2
    non_main_arena = size & 4
    real_size = size & ~0x7  # 去掉标志位后的实际大小

    # print(f"Chunk at {hex(addr)}:")
    # print(f"  prev_size: {prev_size}")
    # print(f"  size: {real_size}")
    # print(f"  flags: prev_inuse={prev_inuse}, is_mmapped={is_mmapped}, non_main_arena={non_main_arena}")
   # 打印堆数据的 ASCII 表示
    data_start = addr + 16  # 跳过 chunk 的元数据部分
    data_end = addr + real_size
    chunk_data = heap_memory[data_start:data_end]

    # # 将数据转换为 ASCII 字符串，过滤不可见字符
    # try:
    #     ascii_data = "".join(
    #         chr(b) if 32 <= b <= 126 else "." for b in chunk_data
    #     )
    #     print(f"  data (ASCII): {ascii_data}")
    # except Exception as e:
    #     print(f"  data (ASCII): <error decoding: {e}>")
        
    return real_size,chunk_data

# test function short path random path
def test1():
        # 示例：解析 graph.dot 文件，查找从 s0 到 s1 的最短路径
    dot_file = "cache/strongswan_v1/learned_model.dot"
    start_node = "s0"
    target_node = "s17"

    shortest_path = find_shortest_path(dot_file, start_node, target_node)
    
    if isinstance(shortest_path, dict):  # 如果找到路径
        # print("Shortest Path (Nodes):", shortest_path["nodes"])
        # print(shortest_path["edges"])
        print("Shortest Path (Edges):")
        for edge in shortest_path["edges"]:
            print(f"  {edge['from']} -> {edge['to']} {edge['input']}")
    else:  # 如果没有路径或发生错误
        print(shortest_path)
    
    random_path = generate_random_path(dot_file, start_node, target_node,15)
    
    if isinstance(random_path, dict):  # 如果找到路径
        # print("random Path (Nodes):", random_path["nodes"])
        # print(random_path["edges"])
        print("random Path (Edges):")
        for edge in random_path["edges"]:
            print(f"  {edge['from']} -> {edge['to']} {edge['input']}")
    else:  # 如果没有路径或发生错误
        print(random_path)
# test function get_heap_mem
def test2():
    remote_host = "192.168.55.137"  # 替换为目标主机 IP
    username = "root"  # 替换为目标主机用户名
    password = "ju"  # 替换为目标主机密码

    # 建立 SSH 连接
    ssh = ssh_connect(remote_host, username, password)
    if not ssh:
        logging.error("ssh connect failed!")
        exit(1)
    get_heap_mem(ssh,'1')



if __name__ == "__main__":
    heap_file = "data_generate/results/strongswan_v1/s0/s0_1.bin"

    
    