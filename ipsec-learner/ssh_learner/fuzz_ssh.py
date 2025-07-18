import socket
import time
import sys, argparse, json, subprocess, os
import traceback
import manualparamiko
from manualparamiko import transport_fuzz
from messages import MSG_MAPPING



class Processor(object):
    ssh_sock = None
    transport = None

    def __init__(self, learnlib, ssh, fuzz_count, json_output_dir, scan_ssh_json_output_dir):
        #Mapper
        self.learnlib_host = learnlib[0]
        self.learnlib_port = learnlib[1]

        #Adapter
        self.ssh_host = ssh[0]
        self.ssh_port = ssh[1]
        self.ssh_username = ssh[2]
        self.ssh_passwd = ssh[3]

        #Timing params (for openSSH)
        #self.auth_ok_to = 3.0
        #self.auth_ok_to_total = 3.3
        #self.auth_nok_to = 0.8
        #self.auth_nok_to_total = 1.0
        #self.cmd_to = 0.25
        #self.global_to = 0.9
        #self.global_to_total = 1.0
        #self.buffer_after_newkey = False

        #Timing params (for BitVise)
        self.auth_ok_to = 3.0
        self.auth_ok_to_total = 3.3
        self.auth_nok_to = 3.5
        self.auth_nok_to_total = 4.0
        self.global_to = 0.2  # 0.2
        self.global_to_total = 0.25  # 0.25
        self.cmd_to = 0.2
        self.buffer_after_newkey = True
        self.fuzz_count = fuzz_count
        self.json_output_dir = json_output_dir
        self.scan_ssh_json_output_dir = scan_ssh_json_output_dir
        self.KEXINIT_keywords = ['cMSG_KEXINIT', '_preferred_kex', 'available_server_keys', '_preferred_ciphers',
                                 '_preferred_macs', '_preferred_compression']
        self.KEX30_keywords = ['c_MSG_KEXDH_INIT']
        self.NEWKEYS_keywords = ['cMSG_NEWKEYS']
        self.SR_AUTH_req_keywords = ['cMSG_SERVICE_REQUEST', 'ssh-userauth']
        self.UA_PW_OK_keywords = ['cMSG_USERAUTH_REQUEST', 'username', 'ssh-connection', 'auth_method', 'password']
        self.channel_open_keywords = ['cMSG_CHANNEL_OPEN', 'kind']
        self.channel_close_keywords = ['cMSG_CHANNEL_CLOSE']
        self.AlgInfos = []
        self.AuthInfos = []
        self.EncTunnelInfos = []
        self.weak_algo = []
        self.normal_process = []
        self.TotalCase = fuzz_count * 19 + 1
        self.DoneCase = 0
        self.ErrorCode = 0
        self.ErrorMsg = ""

    def print_IPsec_fuzz_json_result(self):
        result = {"AlgInfos": {"Name": "SSH Algo_nego test", "KeyLength": "AES-128",
                                               "Safety": "True" if len(self.weak_algo) == 0 else "False",
                                               "SafetyMsg": self.weak_algo,
                                               "Integrity": "True" if len(self.normal_process) == 0 else "False",
                                               "IntegrityMsg": self.normal_process,
                                               "Rubust": "True" if len(self.AlgInfos) == 0 else "False",
                                               "RubustMsg": self.AlgInfos},
                  "AuthInfos": {"Name": "SSH User_auth test", "KeyLength": "AES-128",
                                                 "Safety": "True", "SafetyMsg": [], "Integrity": "True",
                                                 "IntegrityMsg": [],
                                                 "Rubust": "True" if len(self.AuthInfos) == 0 else "False",
                                                 "RubustMsg": self.AuthInfos},
                  "EncTunnelInfos": {"Name": "SSH EncTunnel test", "KeyLength": "AES-128",
                                          "Safety": "True", "SafetyMsg": [], "Integrity": "True", "IntegrityMsg": [],
                                          "Rubust": "True" if len(self.EncTunnelInfos) == 0 else "False",
                                          "RubustMsg": self.EncTunnelInfos},
                  "TotalCase": str(self.TotalCase), "DoneCase": str(self.DoneCase),
                  "ErrorCode": str(self.ErrorCode), "ErrorMsg": self.ErrorMsg}
        json_result = json.dumps(result, indent=4)
        # json_result = demjson.encode(result)
        print(json_result)
        with open(self.json_output_dir, "w") as f:
            f.write(json_result)

    def scan_ssh(self):
        if os.path.exists(self.scan_ssh_json_output_dir):
            os.remove(self.scan_ssh_json_output_dir)
            print "remove old ssh_scan.json file! "
        p = subprocess.Popen(["ssh_scan", "-t", self.ssh_host, "-p", str(self.ssh_port), "-o",
                              self.scan_ssh_json_output_dir], shell=False)
        p.wait()
        time.sleep(3)
        if not os.path.exists(self.scan_ssh_json_output_dir):
            print "ssh_scan.json dosen't exit!"
            self.ErrorCode = 1
            self.ErrorMsg = "ssh_scan failed, ssh_scan.json dosen't exit!"
            self.print_IPsec_fuzz_json_result()
            sys.exit(-1)
        with open(self.scan_ssh_json_output_dir, "r") as f:
            json_result = json.load(f)
            if u'compliance' in json_result[0].keys():
                compliance = json_result[0][u"compliance"]
                if u'recommendations' in compliance.keys():
                    self.weak_algo.append("Weak algos were detected, and we give the following recommendations:")
                    for recommendation in compliance[u'recommendations'.decode()]:
                        self.weak_algo.append(recommendation)
            # print(u'compliance' in json_result[0].keys())
        self.DoneCase += 1
        self.print_IPsec_fuzz_json_result()

    def init_ssh_connection(self, keyword=None):
        """ Create an ssh socket and transport layer object """
        try:
            self.ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssh_sock.connect((self.ssh_host, self.ssh_port))
        except Exception as e:
            print('*** Connect failed: ' + str(e))
            traceback.print_exc()
            sys.exit(1)
        self.transport = transport_fuzz.Transport(self.ssh_sock, auth_ok_to=self.auth_ok_to, auth_ok_to_total=self.auth_ok_to_total, auth_nok_to=self.auth_nok_to, auth_nok_to_total = self.auth_nok_to_total, global_to=self.global_to, global_to_total=self.global_to_total, buffer_after_newkey = self.buffer_after_newkey, username=self.ssh_username, passwd=self.ssh_passwd)
        self.transport.active = True
        try:
            banner = self.transport.fuzz_ssh_version(keyword)
            return banner
        except Exception:
            # print('EXCEPTION. Waiting for old connection to die.')
            # time.sleep(5)
            print "\r\nUnknown Exception!"
            return "None"
        print('SSH-version: %s' % banner)

    def close_ssh_connection(self):
        """ Close the ssh connection """
        if self.ssh_sock:
            self.ssh_sock.close()

    def fuzz_version(self):
        for i in range(self.fuzz_count):
            print("----------------------------------")
            receive = self.init_ssh_connection("version")
            if "SSH" in receive:
                self.AlgInfos.append("fuzz version information value in client proto version message, but reseive " + receive)
            print b'receiced:' + receive
            self.close_ssh_connection()
            self.DoneCase += 1
            self.print_IPsec_fuzz_json_result()

    def fuzz_KEXINIT(self):
        for keyword in self.KEXINIT_keywords:
            for i in range(self.fuzz_count):
                self.init_ssh_connection()
                print("----------------------------------")
                print "sent: KEXINIT message."
                print "key_word:", keyword
                print "normal_value: "
                receive = self.transport.fuzz_kex_init(keyword)
                if receive == "KEXINIT":
                    self.AlgInfos.append("fuzz " + keyword + " in client Key Exchange Init message, but receive " + receive)
                print b'receiced:' + receive
                self.close_ssh_connection()
                self.DoneCase += 1
                self.print_IPsec_fuzz_json_result()

    def fuzz_KEX30(self):
        for keyword in self.KEX30_keywords:
            for i in range(self.fuzz_count):
                self.init_ssh_connection()
                self.transport.fuzz_kex_init()
                print("----------------------------------")
                print "sent: KEX30 message."
                print "key_word:", keyword
                print "normal_value: "
                receive = self.transport.fuzz_kexdh_init(keyword)
                if receive == "KEX31+NEWKEYS":
                    self.AlgInfos.append("fuzz " + keyword + " in client Key Exchange 30 message, but receive " + receive)
                print b'receiced:' + receive
                self.close_ssh_connection()
                self.DoneCase += 1
                self.print_IPsec_fuzz_json_result()

    def fuzz_NEWKEYS(self):
        for keyword in self.NEWKEYS_keywords:
            for i in range(self.fuzz_count):
                self.init_ssh_connection()
                self.transport.fuzz_kex_init()
                self.transport.fuzz_kexdh_init()
                print("----------------------------------")
                print "sent: NEWKEYS message."
                print "key_word:", keyword
                print "normal_value: "
                receive = self.transport.fuzz_newkeys(keyword)
                if receive == "NO_RESP":
                    self.AlgInfos.append("fuzz " + keyword + " in client New Keys message, but receive " + receive)
                print b'receiced:' + receive
                self.close_ssh_connection()
                self.DoneCase += 1
                self.print_IPsec_fuzz_json_result()

    def fuzz_SR_AUTH_req(self):
        for keyword in self.SR_AUTH_req_keywords:
            for i in range(self.fuzz_count):
                self.init_ssh_connection()
                self.transport.fuzz_kex_init()
                self.transport.fuzz_kexdh_init()
                self.transport.fuzz_newkeys()
                print("----------------------------------")
                print "sent: SR_AUTH_req message."
                print "key_word:", keyword
                print "normal_value: "
                receive = self.transport.fuzz_service_request_auth(keyword)
                if receive == "SR_ACCEPT":
                    self.AuthInfos.append("fuzz " + keyword + " in client user auth message, but receive " + receive)
                print b'receiced:' + receive
                self.close_ssh_connection()
                self.DoneCase += 1
                self.print_IPsec_fuzz_json_result()

    def fuzz_UA_PW_OK(self):
        for keyword in self.UA_PW_OK_keywords:
            for i in range(self.fuzz_count):
                self.init_ssh_connection()
                self.transport.fuzz_kex_init()
                self.transport.fuzz_kexdh_init()
                self.transport.fuzz_newkeys()
                self.transport.fuzz_service_request_auth()
                print("----------------------------------")
                print "sent: UA_PW_OK message."
                print "key_word:", keyword
                print "normal_value: "
                receive = self.transport.fuzz_userauth_pw_ok(keyword)
                if receive == "UA_SUCCESS+GLOBAL_REQUEST":
                    self.AuthInfos.append("fuzz " + keyword + " in client user auth passwd message, but receive " + receive)
                print b'receiced:' + receive
                self.close_ssh_connection()
                self.DoneCase += 1
                self.print_IPsec_fuzz_json_result()

    def fuzz_channel_open(self):
        for keyword in self.channel_open_keywords:
            for i in range(self.fuzz_count):
                self.init_ssh_connection()
                self.transport.fuzz_kex_init()
                self.transport.fuzz_kexdh_init()
                self.transport.fuzz_newkeys()
                self.transport.fuzz_service_request_auth()
                self.transport.fuzz_userauth_pw_ok()
                print("----------------------------------")
                print "sent: channel_open message."
                print "key_word:", keyword
                print "normal_value: "
                receive = self.transport.fuzz_channel_open(keyword)
                if receive == "CH_OPEN_SUCCESS":
                    self.EncTunnelInfos.append(
                        "fuzz " + keyword + " in client channel open request message, but receive " + receive)
                print b'receiced:' + receive
                self.close_ssh_connection()
                self.DoneCase += 1
                self.print_IPsec_fuzz_json_result()

    def fuzz_channel_close(self):
        for keyword in self.channel_close_keywords:
            for i in range(self.fuzz_count):
                self.init_ssh_connection()
                self.transport.fuzz_kex_init()
                self.transport.fuzz_kexdh_init()
                self.transport.fuzz_newkeys()
                self.transport.fuzz_service_request_auth()
                self.transport.fuzz_userauth_pw_ok()
                self.transport.fuzz_channel_open()
                print("----------------------------------")
                print "sent: channel_close message."
                print "key_word:", keyword
                print "normal_value: "
                receive = self.transport.fuzz_channel_close(keyword)
                if receive == "CH_CLOSE":
                    self.EncTunnelInfos.append(
                        "fuzz " + keyword + " in client channel close request message, but receive " + receive)
                print b'receiced:' + receive
                self.close_ssh_connection()
                self.DoneCase += 1
                self.print_IPsec_fuzz_json_result()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='target_IP', default='192.168.40.140', help='target_IP (default: 192.168.0.169)')
    parser.add_argument('-P', dest='target_port', default='22', help='target_port (default: 22)')
    parser.add_argument('-u', dest='username', default='root', help='username (default: root)')
    parser.add_argument('-p', dest='passwd', default='pipilu', help='password (default: pipilu)')
    parser.add_argument('-s', dest='fuzz_state', default='3', help='fuzz_state (default: 3)')
    parser.add_argument('-c', dest='fuzz_count', default='5', help='fuzz_count (default: 5)')
    parser.add_argument('-i', dest='iface', default="VMware Virtual Ethernet Adapter for VMnet8", help='iface (default: None)')
    parser.add_argument('-o', dest='json_output_dir', default="./output.json", help='json_output_dir (default: ./output.json)')
    parser.add_argument('-oJ', dest='scan_ssh_json_output_dir', default="./scan_ssh.json",
                        help='scan_ssh_json_output_dir (default: ./scan_ssh.json)')
    args = parser.parse_args()
    sshAdr = (args.target_IP, int(args.target_port), args.username, args.passwd)
    proc = Processor(learnlib=('127.0.0.1', 8000), ssh=sshAdr, fuzz_count=int(args.fuzz_count),
                     json_output_dir=args.json_output_dir, scan_ssh_json_output_dir=args.scan_ssh_json_output_dir)
    try:
        if args.fuzz_state == "1":
            proc.TotalCase = 1
            proc.scan_ssh()
        elif args.fuzz_state == "2":
            proc.TotalCase = proc.fuzz_count * 19
            proc.fuzz_version()
            proc.fuzz_KEXINIT()
            proc.fuzz_KEX30()
            proc.fuzz_NEWKEYS()
            proc.fuzz_SR_AUTH_req()
            proc.fuzz_UA_PW_OK()
            proc.fuzz_channel_open()
            proc.fuzz_channel_close()
        elif args.fuzz_state == "3":
            proc.scan_ssh()
            proc.fuzz_version()
            proc.fuzz_KEXINIT()
            proc.fuzz_KEX30()
            proc.fuzz_NEWKEYS()
            proc.fuzz_SR_AUTH_req()
            proc.fuzz_UA_PW_OK()
            proc.fuzz_channel_open()
            proc.fuzz_channel_close()
        # sys.exit(0)
    except:
        proc.ErrorCode = 1
        if proc.ErrorMsg == "":
            proc.ErrorMsg = "Unknown Exception!"
        proc.print_IPsec_fuzz_json_result()
        print("Unknown Exception!")
        print(traceback.print_exc())
        # print(traceback.format_exc())
        sys.exit(-1)

