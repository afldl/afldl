import glob,os,struct
from PIL import Image
import numpy as np
import h5py
import tqdm


protocol_name = 'openssl12'
# dir = f"data\{protocol_name}"

dir = 'tls12'

all_data = []
labels = []
nums_per_state = 4000

# for state in tqdm.tqdm(os.listdir(dir)):
#     data_paths =  glob.glob(os.path.join(dir,state,"*.png"))
#     # print(data)

select_state = [ f's{i}' for i in range(6)]
for state in tqdm.tqdm(select_state):
    data_paths =  glob.glob(os.path.join(dir,state,"*.png"))[:nums_per_state]
    # print(data)


    for data_path in data_paths:
        image = Image.open(data_path)
        all_data.append(np.array(image))
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
filename = os.path.join(dir,f'{protocol_name}_sample{nums_per_state}_state{len(select_state)}.h5') 
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