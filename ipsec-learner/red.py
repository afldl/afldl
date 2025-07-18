import re,sys,glob,os,pickle
import utils


import sys, time
from learning.StatePrefixEqOracleFailSafe import StatePrefixOracleFailSafe
from learning.FailSafeCacheSUL import FailSafeCacheSUL, print_error_info
from learning.Lstar import ju_run_Lstar
from aalpy.utils import visualize_automaton
from pesp4.IKESUL import *
import simplifyDot
import shutil,json
import pickle
import utils
args_len = len(sys.argv) - 1


print('#'*20)
print('---开始模型学习---')
print('#'*20)


if args_len < 1:
    sys.exit("Too few arguments provided.\nUsage: python3 ipsec_learning.py 'config_file' ")

config_file = sys.argv[1]

with open(config_file,'r',encoding='utf-8') as f:
    config = json.loads(f.read())

# print(config)


IKE_version = config['version']
local_ip = config['local_ip']
remote_ip = config['remote_ip']
iface = config['iface']
out_dir = config['out_dir']
psk = config['psk']
ipsec_config = config['IPSEC_CONFIG']
alphabet = None

if 'alphabet' in config:
    alphabet = config['alphabet']



utils.red_dot(out_dir,IKE_version,alphabet)