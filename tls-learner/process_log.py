# 读取文件
with open('x.txt', 'r') as file:
    lines = file.readlines()

# 创建一个字典来存储每个语句的执行次数
statement_counts = {}

# 遍历每一行并进行计数
for line in lines:
    # print(line)
    statement, count = line.strip().split(': ')
    if statement in statement_counts:
        statement_counts[statement] += int(count)
    else:
        statement_counts[statement] = int(count)

# 输出每个语句和执行次数
print("总共有 {} 个语句".format(len(statement_counts)))
for statement, count in statement_counts.items():
    print("{} 执行了 {} 次".format(statement, count))

