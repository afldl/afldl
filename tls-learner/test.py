import struct

# 假设 heap_memory 是堆内存的数据，addr 是 chunk 的起始地址
heap_memory = bytes.fromhex("00000000000000000000000000010000")
heap_memory = bytes.fromhex("000000000000000080d9490000000000")
addr = 0

# 解析 prev_size 和 size
prev_size = struct.unpack(">Q", heap_memory[addr:addr+8])[0]  # 大端模式
size = struct.unpack(">Q", heap_memory[addr+8:addr+16])[0]     # 大端模式
# 解析 prev_size 和 size
prev_size = struct.unpack("<Q", heap_memory[addr:addr+8])[0]  # 大端模式
size = struct.unpack("<Q", heap_memory[addr+8:addr+16])[0]     # 大端模式
# 检查标志位
prev_inuse = size & 1
is_mmapped = size & 2
non_main_arena = size & 4
real_size = size & ~0x7  # 去掉标志位后的实际大小

# 打印结果
print("prev_size:", prev_size)
print("size:", size)
print("flags: prev_inuse={}, is_mmapped={}, non_main_arena={}".format(prev_inuse, is_mmapped, non_main_arena))
print("real size:", real_size)