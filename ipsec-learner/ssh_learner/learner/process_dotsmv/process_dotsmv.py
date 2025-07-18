# -*- coding: utf-8 -*-

import os
import sys
import struct
import shutil
import subprocess
import argparse, json, traceback, copy
# import time


def search_dot(file_dir):
    for root, dirs, files in os.walk(file_dir):
        for dir in dirs:
            for root1, dirs1, files1 in os.walk(file_dir + "/" + dir):
                for file in files1:
                    if file == "hypothesis-0.dot":
                        return dir
    return None


class process_dotsmv():
    def __init__(self, input_dir, output_dir, json_output_dir):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.json_output_dir = json_output_dir
        self.TestItems = []
        self.TotalCase = 9
        self.DoneCase = 0
        self.ErrorCode = 0
        self.ErrorMsg = ""
        self.NuSMV_head = """*** This is NuSMV 2.6.0 
*** Enabled addons are: compass
*** For more information on NuSMV see <http://nusmv.fbk.eu>
*** or email to <nusmv-users@list.fbk.eu>.
*** Please report bugs to <Please report bugs to <nusmv-users@fbk.eu>>
*** Copyright (c) 2010-2014, Fondazione Bruno Kessler
*** This version of NuSMV is linked to the CUDD library version 2.4.1
*** Copyright (c) 1995-2004, Regents of the University of Colorado
*** This version of NuSMV is linked to the MiniSat SAT solver. 
*** See http://minisat.se/MiniSat.html
*** Copyright (c) 2003-2006, Niklas Een, Niklas Sorensson
*** Copyright (c) 2007-2010, Niklas Sorensson
"""

    def print_IPsec_model_learning_json_result(self):
        result = {"TestItems": self.TestItems, "TotalCase": str(self.TotalCase), "DoneCase": str(self.DoneCase),
                  "ErrorCode": str(self.ErrorCode), "ErrorMsg": self.ErrorMsg}
        json_result = json.dumps(result, indent=4)
        # json_result = demjson.encode(result)
        print(json_result)
        with open(self.json_output_dir, "w") as f:
            f.write(json_result)

    def process(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        else:
            shutil.rmtree(self.output_dir)
            os.makedirs(self.output_dir)
            # 化简状态图
        file_dir = self.input_dir
        if search_dot(file_dir) is None:
            print("there is no hypothesis-0.dot in " + self.input_dir)
            self.ErrorMsg = "there is no hypothesis-0.dot in " + self.input_dir
            self.ErrorCode = 1
            self.print_IPsec_model_learning_json_result()
            sys.exit(-1)
        dot_dir = file_dir + "/" + search_dot(file_dir) + "/" + "hypothesis-0.dot"
        shutil.copyfile(dot_dir, self.output_dir + "/" + "hypothesis-0.dot")
        # 运行命令 python simplify.py
        p = subprocess.Popen("python simplify.py -i " + self.output_dir, shell=True)
        p.wait()
        # 生成状态图
        p = subprocess.Popen("dot -Tpdf -O " + self.output_dir + "/" + "1_preprocess.dot", shell=True)
        p.wait()
        p = subprocess.Popen("dot -Tpdf -O " + self.output_dir + "/" + "hypothesis-0.dot", shell=True)
        p.wait()
        # dot2smv
        p = subprocess.Popen("java -jar dot2smv.jar " + self.output_dir + "/" + "hypothesis-0.dot", shell=True)
        p.wait()
        result = []
        with open('ssh_specification.smv', 'r') as f:
            for i in f.readlines():
                result.append(i)
        with open(args.output_dir + "/" + "hypothesis-0.smv", 'a+') as f:
            for i in result:
                f.write(i)
        try:
            # 运行命令 NuSMV hypothesis-0.smv，并写入文件
            f = os.popen(r"NuSMV " + self.output_dir + "/" + "hypothesis-0.smv", "r")
            d = f.read()  # 读文件
            # print(d)
            # print(type(d))
            f.close()
            with open(self.output_dir + "/" + "out.txt", 'w')as f:
                f.write(d)
            pre_existing_flag = False
            temp_name = ""
            temp_info = ""
            with open(self.output_dir + "/" + "out.txt", 'r')as f:
                for i in f.readlines():
                    if i in self.NuSMV_head or i == "\n" or "This is NuSMV" in i:
                        continue
                    elif "is true" in i:
                        self.TestItems.append({"Name": i[:-9], "UpToStandard": "True", "Critical": "True", "Info": ""})
                        self.DoneCase += 1
                        if pre_existing_flag:  # 之前存在False实例
                            pre_existing_flag = False
                            self.TestItems.append({"Name": temp_name, "UpToStandard": "False",
                                                   "Critical": "True", "Info": temp_info})
                            self.DoneCase += 1
                            temp_name = copy.deepcopy("")
                            temp_info = copy.deepcopy("")
                    elif "is false" in i:
                        if pre_existing_flag:  # 之前存在False实例
                            pre_existing_flag = False
                            self.TestItems.append({"Name": temp_name, "UpToStandard": "False",
                                                   "Critical": "True", "Info": temp_info})
                            self.DoneCase += 1
                            temp_name = copy.deepcopy("")
                            temp_info = copy.deepcopy("")
                        pre_existing_flag = True
                        temp_name = i[:-10]
                    else:
                        temp_info += i
                if temp_name != "":
                    self.TestItems.append({"Name": temp_name, "UpToStandard": "False",
                                       "Critical": "True", "Info": temp_info})
                    self.DoneCase += 1
            self.print_IPsec_model_learning_json_result()
        except:
            print("NuSMV error!")
            print(traceback.print_exc())
            print("Error in NuSMV process, may be DFA is not what we expect")
            self.ErrorMsg = "Error in NuSMV process, may be DFA is not what we expect"
            self.ErrorCode = 1
            self.print_IPsec_model_learning_json_result()
            sys.exit(-1)
        # time.sleep(10)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=" ", epilog=' ')
    # parser.add_argument('-s', dest='salgorithm', default='fa', choices=('fa', 'rr', 'rc', 'lc'),
    #                     help='scheduling algorithm (default: first_available)')
    parser.add_argument('-i', dest='input_dir', default='../output', help='input_dir (default: ../output)')
    parser.add_argument('-o', dest='output_dir', default='./process_result',
                        help='output_dir (default: ./process_result)')
    parser.add_argument('-oj', dest='json_output_dir', default="./output.json",
                        help='json_output_dir (default: ./output.json)')
    args = parser.parse_args()
    my_process = process_dotsmv(args.input_dir, args.output_dir, args.json_output_dir)
    my_process.process()
    sys.exit(0)



##############################################





