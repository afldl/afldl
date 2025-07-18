

import subprocess
from pesp4.IKEv1.IKEv1_client import *
from pesp4.IKEv2.IKEv2_client import *
from scapy.all import *
from operator import methodcaller
import colorama
from colorama import Fore
from aalpy.base import SUL
from utils import str2list
import utils,logging
from pesp4 import enums
from pesp4.ssh import *
logger = logging.getLogger('model learning')

class IKESUL(SUL):
    def __init__(self, my_IP, target_IP, iface,ipsec_config, version='v2', auth_mode=enums.AuthMethod.PSK, cert_file=None, cert_passwd=None,
                impl=None, dir = '', psk='123456',alphabet_map = None,must_query_result=None,restart = False,wait_time = 0,timeout = 0.5):
        super().__init__()
        self.my_IP = my_IP
        self.target_IP = target_IP
        self.iface = iface
        self.version = version
        self.auth_mode = auth_mode
        self.cert_file = cert_file
        self.cert_passwd = cert_passwd
        self.impl = impl
        self.pcap_path = f'{dir}/pcaps'
        self.byte_path = f'{dir}/bytes'
        self.query_path = f'{dir}/query'
        self.passwd = psk
        self.IKE_client = None
        self.alphabet_map = alphabet_map
        self.must_query_result = must_query_result
        self.restart = restart
        self.timeout = timeout
        # print(self.must_query_result)
    
        self.ipsec_config = ipsec_config
        self.wait_time = wait_time

        colorama.init(autoreset=True)
        
    def reset(self):
        if self.impl == 'strongswan':
            reset_strongswan()
            pass
        elif self.impl == 'libreswan':
            reset_libreswan()
            pass
        if self.version == 'v1':
            IKE_attr_values,ESP_attr_values,ESP_T_id,AH_attr_values,AH_T_id = utils.ipsec_config_v1(ipsec_config=self.ipsec_config)
            quick_mode_group_config = None
            if 'quick_mode_group_config' in self.ipsec_config:
                quick_mode_group_config = self.ipsec_config['quick_mode_group_config']
            self.IKE_client = IKEv1_client(self.my_IP, self.target_IP, self.iface, self.passwd,IKE_attr_values=IKE_attr_values,ESP_attr_values=ESP_attr_values,ESP_T_id=ESP_T_id,AH_attr_values=AH_attr_values,AH_T_id=AH_T_id,quick_mode_group_config=quick_mode_group_config,timeout=self.timeout)
        else:
            self.IKE_client = IKEv2_Client(self.my_IP, self.target_IP, self.iface, self.passwd, auth_mode=self.auth_mode, cert_file=self.cert_file, cert_passwd=self.cert_passwd, ipsec_config=self.ipsec_config,timeout=self.timeout)
        return True

    def process_query(self, request):
        # print(f'request: {request}')
        if self.version == 'v1':
            self.IKE_client.current_abstractinput = request
            result = str(methodcaller(default.func_dir[request.replace('*', '')])(self.IKE_client))
        elif self.version == 'v2':
            result = str(self.IKE_client.sendAndRecv(request))
        if 'Response.' in result:
            result = result.replace('Response.', '')
        if 'Notify.' in result:
            result = result.replace('Notify.', '')
        if result == 'No_child_SA' or result == 'No_IKE_SA' or result == 'Have_Rekeyed' or result == 'Un_supported':
            result = 'None'
            # print(self.alphabet_map)
        if self.alphabet_map != None:
            for map1 in self.alphabet_map:
                if result in map1:
                    # print(result)
                    result = map1[result]
                    # print(result)

                    break

        # if result == 'Other':
        #     result = 'No_response'
        # if result == 'Error':
        #     result = 'No_response'  
        # if result == '':
        #     result = 'No_response'          

        logger.info(utils.logger_str(f'{self.IKE_client.current_abstractinput} | {result}'))
        return result
        
    def pre(self):
        attempt_time = 0
        while attempt_time < 5:
            if self.reset():
                break
            attempt_time += 1
        if attempt_time == 5:
            logger.error(Fore.RED + f'reset failed {attempt_time} times')
            sys.exit()
    
    def post(self):
        cmd1 = 'nmcli networking off'
        cmd2 = 'nmcli networking on'
        if self.impl is None and self.IKE_client is not None:
            delESP = 'INFO_DelChild' if self.version == 'v2' else 'delete_ESP'
            delIKE = 'INFO_DelIKE' if self.version == 'v2' else 'delete_IKE'
            self.process_query(delESP)
            self.process_query(delIKE)
        
        time.sleep(self.wait_time)
        if self.restart:
            os.system(cmd1)
            os.system(cmd2)
            time.sleep(0.2)
    
    def step(self, letter):
        logger.info(utils.logger_str("self.step " + letter))
        letter = letter.replace('*', '')
        self.IKE_client.fuzz_replay_data = None
        self.IKE_client.fuzz_replay_mode = False
        self.IKE_client.fuzzing = False
        return self.process_query(letter)
    
    def fuzz_step(self, letter:str):
        letter = letter.replace('*', '')
        self.IKE_client.fuzzing = True
        out = self.process_query(letter)
        abs = self.IKE_client.current_abstractinput
        data = self.IKE_client.current_fuzz_plain
        self.IKE_client.fuzzing = False
        return out, abs, data
    
    def replay_fuzz_step(self, letter:str, fuzz_data):
        self.IKE_client.fuzz_replay_mode = True
        out = self.process_query(letter)
        self.IKE_client.fuzz_replay_mode = False
        return out 
    
    def query(self, word):
        idx = 0
        while True:
            continue_flag = 0
            self.pre()

            out = [self.step(letter) for letter in word]
            # if word[0] == 'SAINIT_SA-KE-NONCE' and out[0] != 'SAINIT_SA-KE-NONCE-4022':
            #     continue
            if self.must_query_result != None:

                for excepted_word,excepted_result in self.must_query_result.items():
                    excepted_word = utils.str2list(excepted_word)
                    excepted_result = utils.str2list(excepted_result)
                    # print(f"word: {word}")
                    # print(f"out: {out}")
                    # print(f"excepted_word: {excepted_word}")
                    # print(f"excepted_result: {excepted_result}")
                    for prelen in range(len(excepted_word)+1):
                        excepted_word2 = excepted_word[:prelen]
                        excepted_result2 = excepted_result[:prelen]
                        if list(word[:len(excepted_word2)]) == excepted_word2 and out[:len(excepted_result2)] != excepted_result2:
                            print(f"word: {word}")
                            print(f"out: {out}")
                            print(f"excepted_word: {excepted_word2}")
                            print(f"excepted_result: {excepted_result2}")
                            idx+=1
                            if idx >= 10:
                                print(f"word: {word}")
                                print(f"out: {out}")
                                print(f"excepted_word: {excepted_word2}")
                                print(f"excepted_result: {excepted_result2}")
                                print('----------------请检查设备活性----------------')

                                logger.info(utils.logger_str(f"word: {word}"))
                                logger.info(utils.logger_str(f"out: {out}"))
                                logger.info(utils.logger_str(f"excepted_word: {excepted_word2}"))
                                logger.info(utils.logger_str(f"excepted_result: {excepted_result2}"))
                                logger.info(utils.logger_str('----------------请检查设备活性----------------'))
                                self.post()
                                sys.exit()
                            continue_flag = 1

            self.post()
            if continue_flag == 1:
                continue
            else:             
                break
        self.num_queries += 1
        self.num_steps += len(word)
        self.performed_steps_in_query = self.num_steps
        return out
    
    def save_pcap(self, name): 
        if not os.path.exists(self.pcap_path):
            os.makedirs(self.pcap_path)       
        self.IKE_client.save_pcap(f'{self.pcap_path}/{name}')
        
    def save_byte(self, name): 
        if not os.path.exists(self.byte_path):
            os.makedirs(self.byte_path)       
        self.IKE_client.save_fuzz_plain(f'{self.byte_path}/{name}')
        
    def read_byte(self, name):
        with open(f'{self.byte_path}/{name}', 'rb') as f:
            data = f.read()
        fuzz_data = []
        i = 0
        while i < len(data):
            length = int.from_bytes(data[i:i+2], byteorder='big')
            one = data[i+2:i+2+length]
            fuzz_data.append(one)
            i += (2 + length)
        # print(fuzz_data)
        return fuzz_data
        
    def save_in_out(self, name, in_out): 
        if not os.path.exists(self.query_path):
            os.makedirs(self.query_path)       
        with open(f'{self.query_path}/{name}.txt', 'w') as file:
            file.write(f'{in_out}')
            
    def read_query_and_prefix(self, name):
        print(f'{self.query_path}/{name}.txt')
        with open(f'{self.query_path}/{name}.txt', 'r') as f:
            lines = f.readlines()
        query = str2list(lines[1].strip('\n'))
        return query

        

