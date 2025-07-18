# -*- coding: UTF-8 -*-

import os
import re
import sys
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=" ", epilog=" ")
    # parser.add_argument('-s', dest='salgorithm', default='fa', choices=('fa', 'rr', 'rc', 'lc'),
    #                     help='scheduling algorithm (default: first_available)')
    parser.add_argument('-i', dest='input_dir', default='.', help='input_file (default: ./)')
    parser.add_argument('-o', dest='output_dir', default='.', help='output_file (default: ./)')
    args = parser.parse_args()


    result = []
    dic = {}
    dic1 = {}
    dic2 = {}
    key = []
    s = ""
    # 读文件，删除None，并按节点存到相应字典里
    with open(args.input_dir + "/hypothesis-0.dot", 'r') as f:
        for i in f.readlines():
            if "None" in i:
                continue
            if re.match("s(\d+) \[", i) or re.match("digraph", i):
                key.append(i)
                continue
            if re.match("s", i) or re.match("label", i):
                dic.setdefault(key[-1], []).append(i)  # {'digraph G {\n': ['label=""\n', 's0\n'...],...,'s13 [label="s13"];\n' :s13 -> s24[label=<<table border="0" cellpadding="1" cellspacing="0"><tr><td>IKE_AUTH_emptyCert</td><td>/</td><td>INVALID_IKE_SPI</td></tr></table>>] }
                continue
            if re.match("\}", i):
                # dic.setdefault(key[0], []).append(i)  # 不往里面放了，最后自己加！
                continue
    # 处理每个节点中重复的内容，所有结果一并输出到result[]中
    # print(dic)
    # for i in dic['s13 [label="s13"];\n']:
    #     print(i)
    result = []
    for i in key:
        if re.match("digraph", i):
            continue
        dic1.clear()
        dic2.clear()
        # print(i)
        if i not in dic:
            # print("一般不会发生这种事" + i)
            continue
        for j in dic[i]:  # 遍历字典中的每个列表，如{"s1":[..->.. , ..->.. , ...]}
            s1 = re.match("s(\d+) -> s(\d+)", j).group()  # s1=s1->s1之类的，即匹配到的部分
            # print(s1)
            if s1 not in dic1:  # 如果第一次出现，则自己对应一个列表，并放进去
                dic1.setdefault(s1, []).append(j)
                continue
            dic1.setdefault(s1, []).append(j)  # 之前出现过了，就放到之前的列表中
        # for ii in dic1.keys():
        #     print(ii)
        #     print(len(dic1[ii]))
            # for jj in dic1[ii]:
            #     print(jj)
        # temp = dic1.keys()
        for j in dic1.keys():
            if len(dic1[j]) == 1:  # 只有一个就不用拆，添了
                dic2.setdefault(j, []).append(dic1[j][0])
                # print(j)
                continue
            # print(j)
            obj2 = re.split("<tr>(.*)</tr>", dic1[j][0])  # 按这个给拆分开， 先把第一个给拆了
            s2 = obj2[0]  # 获取头部，比如s56 -> s56[label=<<table border="0" cellpadding="1" cellspacing="0">
            # print(s2)
            for k in dic1[j]:  # 挑出关键部分给接进去
                # print(k)
                obj = re.search("<tr>(.*)</tr>", k)
                # obj2 = re.split("<tr>(.*)</tr>", k)
                # print(obj.group())
                s2 += obj.group()
                # print(obj2)
                # sys.exit()
            s2 += obj2[-1]
            # print(s2)
            # print(j)
            # del dic1[j]
            dic2.setdefault(j, []).append(s2)  # 替换掉原来集合中的内容
            # for ii in dic1.keys():
            #     print(ii)
            #     print(len(dic1[ii]))
            # print(dic1)
            # sys.exit()
            # print(dic1[j])
        # print(dic1)
        # sys.exit()
        result.append(i)
        for j in dic2.keys():
            result.append(dic2[j][0])
    # 写文件，先把前面的写进去，再写result，最后写\n{
    f = open(args.input_dir + "/1_preprocess.dot", 'w')
    f.write("digraph G {\n")
    f.write("splines=\"line\";\n")
    f.write("concentrate = false;\n")
    f.write("ratio=0.75;\n")
    f.write("node [shape=\"circle\",penwidth=3.0,fontsize=18];\n")
    # f.write("__start0 [label="" shape=\"none\"];\n__start0 -> s0 [label=\"init_IKE / ok\"];")
    for i in dic["digraph G {\n"]:
        f.write(i)
    for i in result:
        f.write(i)
    f.write("}\n")
    # print(dic[key[-1]])
            # if re.match("s(\d+) -> s(\d+)", i):
            #     obj = re.match("s(\d+) -> s(\d+)", i)
            #     print(obj.group())
            #     dic[obj.group()] = i
            #     print()