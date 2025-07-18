from scapy.all import *
from operator import methodcaller
from aalpy.base import SUL
from utils import str2list

class SSHSUL(SUL):
    def __init__(self, ip, port):
        super().__init__()
        self.target_ip = ip
        self.target_port = int(port)
        self.sock = None
        
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        attempt_time = 0
        while attempt_time < 5:
            try:
                self.sock.connect((self.target_ip, self.target_port))
                break
            except Exception as e:
                print("Socket connect error:", str(e))
                attempt_time += 1
        if attempt_time == 5:
            error = f'Socket connect failed {attempt_time} times'
            raise Exception(error)
            
    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        
    def pre(self):
        if not self.sock:
            self.connect()
        
    def post(self):
        self.sock.send("reset".encode())
        response = self.sock.recv(1024).decode().strip('\n')
        print(response)
        
    def step(self, letter:str):
        try:
            self.sock.send(letter.encode())
            response = self.sock.recv(1024).decode().strip('\n')
            if response == 'NO_CONN':
                response = 'NO_RESP'
            print(f'{letter} | {response}')
            return response
        except socket.error as e:
            print("Socket send or receive error:", str(e))
            
    def query(self, word):
        self.pre()
        if len(word) == 0:
            out = [self.step(None)]
        else:
            out = [self.step(letter) for letter in word]
        self.post()
        self.num_queries += 1
        self.num_steps += len(word)
        return out

        

