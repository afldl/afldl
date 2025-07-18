import glob,os,struct
from PIL import Image
import numpy as np
import h5py
import tqdm

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
    # print(f"data(16) : {chunk_data.hex()}")
   # 打印堆数据的 ASCII 表示
    data_start = addr + 16  # 跳过 chunk 的元数据部分
    data_end = addr + real_size
    chunk_data = heap_memory[data_start:data_end]

    
        
    return real_size,chunk_data


def data2fig(data):
    width, length = 300, 300
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
    
    return np.array(img)

protocol_name = 'strongswan_v1'
dir = f"data\{protocol_name}"



all_data = []
labels = []
nums_per_state = 1000
select_state = [ f's{i}' for i in range(5)]

# for state in tqdm.tqdm(os.listdir(dir)):
#     data_paths =  glob.glob(os.path.join(dir,state,"*.bin"))
#     # print(data)

for state in tqdm.tqdm(select_state):
    data_paths =  glob.glob(os.path.join(dir,state,"*.bin"))[:nums_per_state]
    # print(data)


    for data_path in data_paths:
        # image_path = data_path.replace("protocol_name",f"{protocol_name}_image")
        # if not os.path.exists(os.path.dirname(image_path)):
        #     os.makedirs(os.path.dirname(image_path))
        with open(data_path,'rb') as f:
            heap_memory = f.read()
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
        all_data.append(image)
        labels.append(int(state[1:]))

all_data = np.stack(all_data, axis=0, dtype=np.float32)
all_data = np.expand_dims(all_data, axis=1)
labels = np.array(labels)

print(all_data.shape)
print(labels.shape)
# print(labels)

# 获取一个随机排列的索引数组
indices = np.arange(all_data.shape[0])
# 使用 np.random.shuffle 随机打乱这些索引
np.random.shuffle(indices)
# print(indices)

# 根据打乱后的索引重新排列 all_data 和 labels
all_data_shuffled = all_data[indices]
labels_shuffled = labels[indices]

# 打印打乱后的形状以确认
print("\nAfter shuffling:")
print("all_data_shuffled shape:", all_data_shuffled.shape)
print("labels_shuffled shape:", labels_shuffled.shape)

# 定义训练集和测试集的比例
train_ratio = 0.8
split_index = int(train_ratio * len(all_data_shuffled))

# 分割数据为训练集和测试集
train_data = all_data_shuffled[:split_index]
train_labels = labels_shuffled[:split_index]
test_data = all_data_shuffled[split_index:]
test_labels = labels_shuffled[split_index:]

# 打印分割后的形状以确认
print("\nAfter shuffling and splitting:")
print("train_data shape:", train_data.shape)
print("train_labels shape:", train_labels.shape)
print("test_data shape:", test_data.shape)
print("test_labels shape:", test_labels.shape)

# 定义要保存的文件名
filename = os.path.join(dir,f'data_sample{nums_per_state}_state{len(select_state)}.h5') 
# 使用 h5py 创建一个新的 HDF5 文件并写入数据
with h5py.File(filename, 'w') as f:
    # 创建数据集并将 all_data 写入文件
    dset_data = f.create_dataset('train_data', data=train_data, compression="gzip", compression_opts=9)
    
    # 创建数据集并将 labels 写入文件
    dset_labels = f.create_dataset('train_labels', data=train_labels, compression="gzip", compression_opts=9)

    dset_data2 = f.create_dataset('test_data', data=test_data, compression="gzip", compression_opts=9)
    
    # 创建数据集并将 labels 写入文件
    dset_labels2 = f.create_dataset('test_labels', data=test_labels, compression="gzip", compression_opts=9)


print(f"Data and labels have been saved to {filename}")


# 加载 HDF5 文件中的数据
with h5py.File(filename, 'r') as f:
    loaded_all_data = f['train_data'][:]
    loaded_labels = f['train_labels'][:]

# 确认加载的数据与原始数据一致
print("Loaded data shape:", loaded_all_data.shape)
print("Loaded labels shape:", loaded_labels.shape)

print(labels_shuffled)