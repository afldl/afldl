import socket
import time
import sys
import traceback
import manualparamiko
from manualparamiko import transport
from messages import MSG_MAPPING



class Processor(object):
    ssh_sock = None
    transport = None

    def __init__(self, learnlib, ssh, fuzz_count):
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
        self.global_to = 0.2
        self.global_to_total = 0.25
        self.cmd_to = 0.2
        self.buffer_after_newkey = True
        self.fuzz_count = fuzz_count
        self.KEXINIT_keywords = ['cMSG_KEXINIT', '_preferred_kex', 'available_server_keys', '_preferred_ciphers',
                                 '_preferred_macs', '_preferred_compression']
        self.KEX30_keywords = ['c_MSG_KEXDH_INIT']
        self.NEWKEYS_keywords = ['cMSG_NEWKEYS']
        self.SR_AUTH_req_keywords = ['cMSG_SERVICE_REQUEST', 'ssh-userauth']
        self.UA_PW_OK_keywords = ['cMSG_USERAUTH_REQUEST', 'username', 'ssh-connection', 'auth_method', 'password']
        self.channel_open_keywords = ['cMSG_CHANNEL_OPEN', 'kind']
        self.channel_close_keywords = ['cMSG_CHANNEL_CLOSE']

    def init_ssh_connection(self, keyword=None):
        """ Create an ssh socket and transport layer object """
        try:
            self.ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssh_sock.connect((self.ssh_host, self.ssh_port))
        except Exception as e:
            print('*** Connect failed: ' + str(e))
            traceback.print_exc()
            sys.exit(1)
        self.transport = transport.Transport(self.ssh_sock, auth_ok_to=self.auth_ok_to, auth_ok_to_total=self.auth_ok_to_total, auth_nok_to=self.auth_nok_to, auth_nok_to_total = self.auth_nok_to_total, global_to=self.global_to, global_to_total=self.global_to_total, buffer_after_newkey = self.buffer_after_newkey, username=self.ssh_username, passwd=self.ssh_passwd)
        self.transport.active = True
        try:
            banner = self.transport.fuzz_ssh_version()
            return banner
        except Exception:
            print('EXCEPTION. Waiting for old connection to die.')
            time.sleep(5)
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
            print b'receiced:' + receive
            self.close_ssh_connection()

    def fuzz_KEXINIT(self):
        for keyword in self.KEXINIT_keywords:
            for i in range(self.fuzz_count):
                self.init_ssh_connection()
                print("----------------------------------")
                print "sent: KEXINIT message."
                print "key_word:", keyword
                print "normal_value: "
                receive = self.transport.fuzz_kex_init(keyword)
                print b'receiced:' + receive
                self.close_ssh_connection()

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
                print b'receiced:' + receive
                self.close_ssh_connection()

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
                print b'receiced:' + receive
                self.close_ssh_connection()

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
                print b'receiced:' + receive
                self.close_ssh_connection()

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
                print b'receiced:' + receive
                self.close_ssh_connection()

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
                print b'receiced:' + receive
                self.close_ssh_connection()

    def fuzz_channel_close(self):
        self.init_ssh_connection()
        self.transport.fuzz_kex_init()
        self.transport.fuzz_kexdh_init()
        self.transport.fuzz_newkeys()
        self.transport.fuzz_service_request_auth()
        self.transport.fuzz_userauth_pw_ok()
        self.transport.fuzz_channel_open()
        self.close_ssh_connection()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sshServerIP = sys.argv[1]
    else:
        sshServerIP = "192.168.0.140"
    if len(sys.argv) > 2:
        sshServerPort = int(sys.argv[2])
    else:
        sshServerPort = 22
    if len(sys.argv) > 3:
        sshUsername = sys.argv[3]
    else:
        sshUsername = "root"
    if len(sys.argv) > 4:
        sshPasswd = sys.argv[4]
    else:
        sshPasswd = "pipilu123456"
    if len(sys.argv) > 5:
        fuzz_count = int(sys.argv[5])
    else:
        fuzz_count = 5

    sshAdr = (sshServerIP, sshServerPort, sshUsername, sshPasswd)
    proc = Processor(learnlib=('127.0.0.1', 8000), ssh=sshAdr, fuzz_count=fuzz_count)
    proc.fuzz_channel_close()

    # proc.listen()