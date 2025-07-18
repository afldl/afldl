#!/usr/bin/env python
#-*- encoding:utf-8 -*-
import socket
import subprocess
import signal
import os
import struct
import time
import sys
import argparse, traceback, copy, json


class daemon():
    def __init__(self, target_IP, target_port, username, passwd, output_dir, json_output_dir):
        self.target_IP = target_IP
        self.target_port = target_port
        self.username = username
        self.passwd = passwd
        self.output_dir = output_dir
        self.json_output_dir = json_output_dir
        self.TotalCase = 784
        self.DoneCase = 0
        self.ErrorCode = 0
        self.ErrorMsg = ""
        self.IsComplete = "False"
        self.no_msg_count = 0
        self.cache_count = 2  # 第一个不是cache

    def print_model_learning_json_result(self):
        result = {"TotalCase": str(self.TotalCase), "DoneCase": str(self.DoneCase),
                  "ErrorCode": str(self.ErrorCode), "ErrorMsg": self.ErrorMsg, "IsComplete": self.IsComplete}
        json_result = json.dumps(result, indent=4)
        print(json_result)
        with open(self.json_output_dir, "w") as f:
            f.write(json_result)

    def model_learning(self):
        try:
            pyProcess = subprocess.Popen(["python2", "mapper.py", self.target_IP, self.target_port,
                                          self.username,  self.passwd],
                                         )
            time.sleep(1)
            print(f"mapper_pid:{pyProcess.pid}")
            javaProcess = subprocess.Popen(["java", "-jar", "ssh_learner_10_13.jar", self.output_dir + "/"],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           cwd="./learner")
            print(f"learner_pid:{javaProcess.pid}")
            self.last_time = time.time()
            while True:
                msg = javaProcess.stdout.readline()
                javaProcess.stdout.flush()
                exit_code = subprocess.Popen.poll(javaProcess)
                if exit_code is not None:  # java_process end, then kill py_process
                    print(f"exit_code:{exit_code}")
                    if subprocess.Popen.poll(pyProcess) is not None:
                        pyProcess.terminate()
                        print("kill Python process.")
                    print("Python process is killed.")
                    if exit_code == 2:
                        self.IsComplete = "True"
                        self.print_model_learning_json_result()
                        return 0
                    break
                if self.cache_count < 0 and self.DoneCase % 100 == 99:  # self.cache_count < 0 表示已经不是cache
                    javaProcess.stdout.flush()
                if not msg:  # process end
                    print("no msg, no_msg_count +1 !")
                    self.no_msg_count += 1
                    time.sleep(1)
                    print(self.no_msg_count)
                    if self.no_msg_count >= 10000:
                        self.no_msg_count = 1
                        if subprocess.Popen.poll(pyProcess) is None:
                            pyProcess.terminate()
                            print("kill Python process.")
                        print("Python process killed.")
                        if subprocess.Popen.poll(javaProcess) is None:
                            javaProcess.terminate()
                            print("kill Java process.")
                        print("Java process killed.")
                        return
                msg = msg.strip()
                s = str(msg)
                if self.cache_count >= 0 and "using cache" in s:
                    self.cache_count += 1
                if "QUERY #" in s:
                    if self.cache_count >= 0:
                        print("cache!!!!!!!!!!!!!!!!!!!!")
                        self.cache_count -= 1
                    print(type(s))
                    print(s)
                    DoneCase = ""
                    for c in s:
                        if c == "(":
                            break
                        if c in "0123456789":
                            DoneCase += c
                    self.DoneCase = int(DoneCase)
                    self.print_model_learning_json_result()

                print(msg)
            print("process finished normally.")
        except Exception:
            print("Unknown Exception!")
            print(traceback.print_exc())
            if subprocess.Popen.poll(pyProcess) is None:
                pyProcess.terminate()
                print("kill Python process.")
            print("Python process killed.")
            if subprocess.Popen.poll(javaProcess) is None:
                javaProcess.terminate()
                print("kill Java process.")
            print("Java process killed.")
            print("Done.")
        finally:
            if subprocess.Popen.poll(pyProcess) is None:
                pyProcess.terminate()
                print("kill Python process.")
            print("Python process killed.")
            if subprocess.Popen.poll(javaProcess) is None:
                javaProcess.terminate()
                print("kill Java process.")
            print("Java process killed.")
            print("Done.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='target_IP', default='192.168.40.140', help='target_IP (default: 192.168.40.132)')
    parser.add_argument('-P', dest='target_port', default='22', help='target_port (default: 22)')
    parser.add_argument('-u', dest='username', default='root', help='username (default: root)')
    parser.add_argument('-p', dest='passwd', default='pipilu123456', help='password (default: pipilu123456)')
    parser.add_argument('-o', dest='output_dir', default="./output", help='json_output_dir (default: ./output)')
    parser.add_argument('-oj', dest='json_output_dir', default="./output.json", help='json_output_dir (default: ./output.json)')
    args = parser.parse_args()
    my_process = daemon(args.target_IP, args.target_port, args.username, args.passwd, args.output_dir, args.json_output_dir)
    try:
        while True:
            if my_process.model_learning() == 0:
                break
    except Exception:
        my_process.ErrorCode = 1
        my_process.ErrorMsg = "Unknown Error"
        my_process.print_model_learning_json_result()
        print(traceback.print_exc())
        sys.exit(-1)

