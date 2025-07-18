from random import *
import struct
from operator import methodcaller
import random
fuzz_operator={
    0:'truncating_operator',
    1:'removing_operator',
    2:'duplicating_operator',
    3:'contentfuzz_operator',
    4:'randomstring_operator'
}
def randomstring(length=4):
    a = "".join([choice("0123456789ABCDEF") for i in range(2*length)])
    #print('a=',a)
    if length == 1:
        return struct.pack('B',int(a,16))
    if length == 2:
        return struct.pack('H',int(a,16))
    if length == 4:
        return struct.pack('L',int(a,16))
    if length == 8:
        return struct.pack('Q',int(a,16))
    if length == 0:
        return b''
    return bytes.fromhex(a)

def zerostring(length=4):
    if length == 1:
        return struct.pack('B',0)
    if length == 2:
        return struct.pack('H',0)
    if length == 4:
        return struct.pack('L',0)
    if length == 8:
        return struct.pack('Q',0)
    if length == 0:
        return b''
    return bytes.fromhex(a)

def get_r(keyword, pkt_len):
    if keyword=='truncating_operator':
        return {'truncating_operator':random.randint(40, pkt_len)}
    if keyword=='removing_operator':
        return {'removing_operator':[random.randint(1, pkt_len),random.randint(1,10)]}
    if keyword=='duplicating_operator':
        return {'duplicating_operator': [random.randint(1, pkt_len), random.randint(1, 10)]}
    if keyword=='contentfuzz_operator':
        return {'contentfuzz_operator': [random.randint(0, pkt_len),randomstring(choice([1,2,4,8])),choice([1,2,4,8])]}
    if keyword=='randomstring_operator':
        return {'randomstring_operator': [random.randint(0, pkt_len),randomstring(random.randint(0, 16)),random.randint(1, 10)]}

class random_fuzz():
    def __init__(self):
        self.random_seed=None
        self.packet = None
        self.corpus=None

    def truncating_operator(self):
        pkt_len = len(self.packet)
        # print(pkt_len)
        cur_len=random.randint(40, pkt_len)
        return self.packet[0:cur_len]

    def truncating_operator1(self,key):
        # print(key['truncating_operator'])
        return self.packet[0:key['truncating_operator']]

    def removing_operator(self):
        pkt_len = len(self.packet)
        cur_len = random.randint(1, pkt_len)
        cur2_len = random.randint(1,10)
        return self.packet[0:cur_len]+self.packet[cur_len+cur2_len:]

    def removing_operator1(self,key):
        return self.packet[0:key['removing_operator'][0]]+self.packet[key['removing_operator'][0]+key['removing_operator'][1]:]

    def duplicating_operator(self):
        pkt_len = len(self.packet)
        cur_len = random.randint(0, pkt_len)
        cur2_len = random.randint(0,10)
        return self.packet[0:cur_len]+self.packet[cur_len:cur2_len]+self.packet[cur_len:cur2_len]+self.packet[cur2_len:]

    def duplicating_operator1(self,key):

        return self.packet[0:key['duplicating_operator'][0]]+self.packet[key['duplicating_operator'][0]:key['duplicating_operator'][0]+key['duplicating_operator'][1]]+self.packet[key['duplicating_operator'][0]:key['duplicating_operator'][0]+key['duplicating_operator'][1]]+self.packet[key['duplicating_operator'][0]+key['duplicating_operator'][1]:]

    def contentfuzz_operator(self):
        cho=[1,2,4,8]
        l=choice(cho)
        # print(l)
        # l = randomstring(choice(cho))
        # print(len(l))
        pkt_len = len(self.packet)
        cur_loc = random.randint(0, pkt_len)
        forward = self.packet[0:cur_loc]
        mid = randomstring(choice(cho))
        end = self.packet[cur_loc + 4:]
        return forward + mid + end

    def contentfuzz_operator1(self,key):
        # print(key)
        forward = self.packet[0:key['contentfuzz_operator'][0]]
        mid = key['contentfuzz_operator'][1]
        end = self.packet[key['contentfuzz_operator'][0]+key['contentfuzz_operator'][2]:]
        return forward + mid + end

    def randomstring_operator(self):
        pkt_len = len(self.packet)
        cur_loc = random.randint(0, pkt_len)
        forward = self.packet[0:cur_loc]
        cur2_len = random.randint(0, 20)
        random_len = random.randint(0,40)
        # ranbit=self.random_seed.read(random_len)
        ranbit=randomstring(random_len)
        # print(ranbit)
        return forward+ranbit+self.packet[cur_loc+cur2_len:]

    def randomstring_operator1(self, key):
        forward = self.packet[0:key['randomstring_operator'][0]]
        mid = key['randomstring_operator'][1]
        end = self.packet[key['randomstring_operator'][0] + key['randomstring_operator'][2]:]
        return forward + mid + end









