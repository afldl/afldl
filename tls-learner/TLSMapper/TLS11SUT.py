import subprocess
from TLSMapper.mytls11 import *
import time,datetime
import colorama
from colorama import Fore
from operator import methodcaller
from fuzzing.LTLfSUT import *
from LTLf.TLS13LTLfFormulas import *

class TLS11SUT(LTLfSUT):
    def __init__(self, keyfile=None, certfile=None, ciphersuites=None, target_cmd=None):
        super().__init__()
        self.load_key_and_cert(keyfile, certfile)
        self.ciphersuites = ciphersuites
        self.TLS_client=None
        self.target_cmd = target_cmd
        self.target_process = None
    
    def load_key_and_cert(self, keyfile, certfile):
        if keyfile is None or certfile is None:
            self.privateKey = None
            self.cert_chain = None
            return 
        try:
            text_key = str(open(keyfile, 'rb').read(), 'utf-8')
            self.privateKey = parsePEMKey(text_key, private=True,implementations=["python"])
            text_cert = str(open(certfile, 'rb').read(), 'utf-8')
            self.cert_chain = X509CertChain()
            self.cert_chain.parsePemList(text_cert)
        except Exception as e:
            print(f'wrong keyfile or certfile!{e}')
        
    def reset(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect(('127.0.0.1',4433))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.TLS_client = TLSClient11(sock, ciphersuites=self.ciphersuites, privateKey=self.privateKey, cert_chain=self.cert_chain)
        #self.TLS_client.pre_set_extensions=[[(3,0)],[GroupName.x25519,GroupName.secp256r1],[(6,1),(5,1),(4,1),(6,3),(5,3),(4,3)]] # [versions,groups,sig_algs]

        self.TLS_client.settings=HandshakeSettings().validate()
        return True

    def process_query(self, letter):
        response = self.TLS_client.sendAndRecv(letter)
        if response in ['UnSupported', 'SendFailed', 'SigFailed', 'NoClientCert']:
            return 'None'
        return response
     
    def pre(self):
        if self.target_cmd:
            self.target_process = subprocess.Popen(self.target_cmd, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.1)
        self.reset()
    
    def target_process_exception(self):
        res = self.target_process.poll()
        print(res)
        if res is None:
            return False
        elif res == 0:
            return False
        else:
            return True
        
    def post(self):
        if self.target_process:
            self.target_process.terminate()
            self.target_process.wait()
            self.target_process = None    
    
    def step(self, letter):
        response = self.process_query(letter)
        print(f'{letter} | {response}')
        return response
    
    def query(self, word):
        print('*'*100)
        print(f'current query : {word}')
        self.pre()
        if len(word) == 0:
            out = [self.step(None)]
        else:
            out = [self.step(letter) for letter in word]
        self.post()
        self.num_queries += 1
        self.num_steps += len(word)
        self.performed_steps_in_query = self.num_steps
        return out
    
    def fuzz_step(self, letter:str):
        self.TLS_client.fuzz_mode = True
        fletter = f'{letter}*'
        response = self.process_query(letter)
        self.TLS_client.fuzz_mode = False
        print(f'{letter} | {response}')
        return fletter, response
    
    def replay_fuzz_step(self, letter:str):
        print(letter)
        if '*' in letter:
            self.TLS_client.fuzz_replay_mode = True
            rletter = letter.replace('*', '')
            response = self.process_query(rletter)
        else:
            response = self.process_query(letter)
        self.TLS_client.fuzz_replay_mode = False
        print(f'{letter} | {response}')
        return letter, response
    
    def save_pcap(self, name): 
        self.TLS_client.save_pcap(name)
        
    def save_fuzz_contents(self, name):   
        xml_content = ET.tostring(self.TLS_client.fuzz_contents, encoding='utf-8').decode('utf-8')
        dom = xml.dom.minidom.parseString(xml_content)
        pretty_xml = dom.toprettyxml()
        with open(name, 'w') as f:
            f.write(pretty_xml)
        
    def read_fuzz_contents(self, name):
        tree = ET.parse(name)
        self.TLS_client.fuzz_replay_content = tree.getroot()
            
    def sut_to_ltl_map(self, symbol_name, is_request:bool):
        symbol = Symbol(symbol_name, is_request)
        return tls_sut_to_ltl_map(symbol).name
    
    def ltl_to_sut_map(self, symbol_name):
        return tls_ltl_to_sut_map(symbol_name)
        

