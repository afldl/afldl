import random
import networkx as nx
import os
import subprocess
import struct
import paramiko
import logging
from PIL import Image
import numpy as np
from collections import deque
import string
from collections import OrderedDict

def read_heap_memory(pid, start_address, end_address, output_file):
    try:
        # 本地路径
        mem_path = f"/proc/{pid}/mem"
        tmp_file = 'tmp.bin'
        # 确保输出文件所在的目录存在
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
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
        
        # 执行命令并捕获输出
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0:
            error = result.stderr.strip()
            if 'cannot skip to specified offset' not in error:
                logging.error(f"命令执行失败: {error}")
                return False
        
        logging.info(f"成功将本地进程 {pid} 的堆内存保存到文件 {tmp_file}")
        with open(tmp_file,'rb') as f:
            heap_memory = f.read()
        os.remove(tmp_file)
        img = bin2img2(heap_memory)
        img.save(output_file)


        return True
    except Exception as e:
        logging.error(f"发生错误: {e}")
        return False

def is_printable(s):
    """检查给定的bytes对象是否全部由可打印字符组成"""
    return all(32 <= b <= 126 or b == 0 for b in s)


def parse_chunk_all(heap_memory):
    chunk_data = []
    length = len(heap_memory)
    
    i = 0
    while i < length:
        # 确保不会超出索引范围
        end = min(i + 16, length)
        chunk = heap_memory[i:end]
        
        # 如果长度不足16位，直接添加到结果中
        if len(chunk) < 16:
            chunk_data.extend(chunk)
            break
        
        # 检查当前chunk是否全为0
        if all(b == 0 for b in chunk):
            pass  # 当前块全为0，跳过
        # 检查当前chunk是否由可打印字符加0组成
        elif is_printable(chunk):
            pass  # 当前块为字符串+0，跳过
        else:
            # 否则，将当前块添加到结果列表中
            chunk_data.extend(chunk)
        
        # 移动到下一个16字节块
        i += 16
    
    return chunk_data



# 解析 malloc_chunk 的函数
def parse_chunk(heap_memory, addr):
    # 解析 malloc_chunk 的 prev_size 和 size
    prev_size = struct.unpack("<Q", heap_memory[addr:addr+8])[0]
    size = struct.unpack(">Q", heap_memory[addr+8:addr+16])[0]
    
    # 检查标志位
    prev_inuse = size & 1
    is_mmapped = size & 2
    non_main_arena = size & 4
    real_size = size & ~0x7  # 去掉标志位后的实际大小



    # print(f"Chunk at {hex(addr)}:")
    # print(f"  prev_size: {prev_size}")
    # print(f"  size: {real_size}")
    # print(f"  flags: prev_inuse={prev_inuse}, is_mmapped={is_mmapped}, non_main_arena={non_main_arena}")
#    打印堆数据的 ASCII 表示
        
    if real_size > 16:
        data_start = addr + 16  # 跳过 chunk 的元数据部分
        data_end = addr + real_size
        chunk_data = heap_memory[data_start:data_end]

        print(f"first 16 data {heap_memory[addr:addr+16].hex()}")

    else:
        chunk_data = b""  # 如果 real_size 不合理，返回空数据

    initialized = False
    # 判断是否被初始化
    if real_size > 32:
        initialized = True

        # 检查 footer
        footer_addr = addr + real_size - 8
        if footer_addr >= len(heap_memory):
            footer_valid = False
        else:
            footer = struct.unpack("<Q", heap_memory[footer_addr:footer_addr+8])[0] & ~0x7
            footer_valid = footer == real_size
        # if not footer_valid:
        #     initialized = False
        if all(c == 0 for c in chunk_data):  # 全部为零可能表示未初始化
            initialized = False
        if all(c in string.printable.encode() for c in chunk_data):
            initialized = False


    print(f"real size: {real_size}")
    print(f"initialized: {initialized}")
    # 将数据转换为 ASCII 字符串，过滤不可见字符
    try:
        ascii_data = "".join(
            chr(b) if 32 <= b <= 126 else "." for b in chunk_data
        )
        print(f"  data (ASCII): {ascii_data}")
    except Exception as e:
        print(f"  data (ASCII): <error decoding: {e}>")



    return real_size,chunk_data,initialized



def bin2img(heap_memory):

    data = []
    addr = 0
    add_data_size = 0
    while addr < len(heap_memory):
        try:
            chunk_size, chunk_data, initialized = parse_chunk(heap_memory, addr)
    
            if chunk_size is None:
                break
            if chunk_size == 0:
                addr += 16
                print(f"addr : {addr}")
                print(f"add_data_size: {add_data_size}")
                continue
            if chunk_size > 32 and initialized:
                # 将数据块转换为不可变类型（元组）以用于字典键
                    data.append(chunk_data)
                    add_data_size  += chunk_size
            addr += chunk_size
            print(f"addr : {addr}")
            print(f"add_data_size: {add_data_size}")

        except struct.error:
            print(f"[-] Failed to parse chunk at {hex(addr)}. Stopping.")
            break

        print(f"skip_size : {addr}\n")
        print(f"heap_info.size : {len(heap_memory)}\n",)
        print("\n")

    
    image = data2fig(data)
    return image


# just get all data
def bin2img2(heap_memory):
    width, length = 450, 450
    total_pixels = width*length
    chunk_data= parse_chunk_all(heap_memory)

    # 如果数据不足，则用0填充至所需的总像素数量
    print(len(chunk_data))
    if len(chunk_data) < total_pixels:
        chunk_data.extend([0] * (total_pixels - len(chunk_data)))
    
    

    # 确保我们只使用正好需要的像素数
    chunk_data = chunk_data[:total_pixels]
    
    # 创建一个新的300x300灰度图像
    img = Image.new('L', (width, length))
    
    # 将数据映射到图像中
    img.putdata(chunk_data)
    
    return img




def data2fig(data):
    width, length = 600, 600 
    total_pixels = width * length
    
    # 初始化一个空列表用于存储处理后的像素值
    pixel_data = []
    
    # 遍历输入的二进制数据列表，提取每个字节作为一个像素点
    for item in data:
        # 将每个数据项转换为bytearray以便于迭代
        byte_array = bytearray(item)
        # 添加到pixel_data中

        # 如果byte_array末尾有超过或等于50个0，则去掉这些0
        while len(byte_array) >= 20 and all(x == 0 for x in byte_array[-50:]):
            byte_array = byte_array.rstrip(b'\x00')  # 去掉末尾的0

        pixel_data.extend(byte_array)

        # 如果在处理过程中已经收集了足够的像素，则停止
        # if len(pixel_data) >= total_pixels:
        #     break
    
    # 如果数据不足，则用0填充至所需的总像素数量
    print(len(pixel_data))
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
        remote_output_file = f"/tmp/1.bin"  # 临时文件存储在远程主机的 /tmp 目录
        
        # 创建命令来读取内存数据
        heap_size = end_address - start_address
        command = (
            f"dd if={remote_mem_path} bs=1 skip={start_address} count={heap_size} of={remote_output_file}"
        )
        # print(command)
        # 在远程主机执行命令
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout.channel.recv_exit_status()  # 等待命令执行完成
        
        # 检查错误
        error = stderr.read().decode()
        if error and 'cannot skip to specified offset' not in error:
            logging.error(f"远程命令执行失败: {error}")
            return False
        
        # 将远程文件下载到本地
        sftp = ssh.open_sftp()
        sftp.get(remote_output_file, output_file)
        sftp.close()
        rm_command = (
            f"rm {remote_output_file}"
        )
        # print(rm_command)
        stdin, stdout, stderr = ssh.exec_command(rm_command)
        stdout.channel.recv_exit_status()  # 等待命令执行完成
        logging.info(f"成功将远程进程 {pid} 的堆内存保存到本地文件 {output_file}")
        return True
    except Exception as e:
        logging.error(f"发生错误: {e}")
        return False


def get_heap_address_range(pid):
    try:
        # 本地路径
        maps_path = f"/proc/{pid}/maps"
        
        # 直接读取文件
        with open(maps_path, 'r') as file:
            for line in file:
                if "[heap]" in line:
                    # 提取地址范围
                    address_range = line.split()[0]
                    start_address, end_address = address_range.split("-")
                    return int(start_address, 16), int(end_address, 16)
        
        logging.error("未找到堆地址范围。")
        return None, None
    except FileNotFoundError:
        logging.error(f"文件 {maps_path} 不存在。")
        return None, None
    except Exception as e:
        logging.error(f"发生错误: {e}")
        return None, None




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

def get_pid(pname):
    try:
        # 使用 pgrep 查找指定进程的 PID
        command = ["pgrep", pname]
        
        # 执行命令并捕获输出
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:  # 如果找到了匹配的进程
            pids = result.stdout.strip().split('\n')
            if pids and pids[0]:  # 确保有PID且非空
                return int(pids[0])  # 返回第一个 PID
            else:
                logging.error(f"未找到 {pname} 进程。")
                return None
        else:
            logging.error(f"未找到 {pname} 进程。")
            return None
        
    except Exception as e:
        logging.error(f"获取 {pname} PID 时发生错误: {e}")
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

def generate_unique_paths(graph, src, dst, num_paths,max_len):
    if src not in graph or dst not in graph:
        return f"Source node '{src}' or destination node '{dst}' not found in the graph."

    # 检查是否存在从 src 到 dst 的路径
    if not nx.has_path(graph, src, dst):
        return f"No path exists from {src} to {dst}."

    paths = []  # 存储找到的路径
    queue = deque([[src]])  # 使用队列存储当前所有可能的路径

    while queue and len(paths) < num_paths:
        current_path = queue.popleft()
        current_node = current_path[-1]
        if len(current_path) > max_len:
            continue
        # 如果当前节点是目标节点，保存这条路径
        if current_node == dst:
            paths.append(current_path.copy())

        # 获取当前节点的所有邻居
        neighbors = list(graph.successors(current_node))

        # 遍历每个邻居，将其添加到路径中，并将新路径加入队列
        for neighbor in neighbors:
            new_path = current_path + [neighbor]
            queue.append(new_path)

    # 将路径转换为所需的格式
    result = []
    for path in paths:
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

        result.append({
            "nodes": path,  # 节点路径
            "edges": edge_data  # 边上的数据
        })

    return result

def generate_random_path_from_dot(dot_file, src, dst, max_length):
    # 解析 .dot 文件为有向图
    graph = nx.DiGraph(nx.nx_pydot.read_dot(dot_file))
    return generate_random_path(graph,src, dst, max_length)

def get_heap_mem_local(pname,output_file):
    pid = get_pid(pname)

    start_address, end_address = get_heap_address_range(pid)
    if start_address is None or end_address is None:
        print("cann't get heap address!")
        exit(1)
    if read_heap_memory(pid, start_address, end_address, output_file):
        logging.info(f"堆内存已保存到本地文件: {output_file}")

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



# test function short path random path
def test1():
        # 示例：解析 graph.dot 文件，查找从 s0 到 s1 的最短路径
    dot_file = "tls12.dot"
    start_node = "s0"
    target_node = "s3"

    shortest_path = find_shortest_path(dot_file, start_node, target_node)
    
    if isinstance(shortest_path, dict):  # 如果找到路径
        # print("Shortest Path (Nodes):", shortest_path["nodes"])
        # print(shortest_path["edges"])
        print("Shortest Path (Edges):")
        for edge in shortest_path["edges"]:
            print(f"  {edge['from']} -> {edge['to']} {edge['input']}")
    else:  # 如果没有路径或发生错误
        print(shortest_path)
        # 解析 .dot 文件为有向图
    graph = nx.DiGraph(nx.nx_pydot.read_dot(dot_file))
    random_path = generate_random_path(graph, start_node, target_node,15)
    
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

    get_heap_mem_local('openssl','1')


def test3():

    dot_file = "tls12.dot"
    start_node = "s0"
    target_node = "s5"
    graph = nx.DiGraph(nx.nx_pydot.read_dot(dot_file))
    paths = generate_unique_paths(graph,start_node,target_node,100,20)
    # print(paths)
    print(len(paths))


if __name__ == "__main__":
    # test1()
    # heap_file = "data_generate/results/strongswan_v1/s0/s0_1.bin"
    # test2()
    test3()


    
    