import os
import sys

# 获取当前脚本所在的目录，并添加到系统路径中
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.abspath(current_dir))
# os.chdir(parent_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)
if current_dir in sys.path:
    sys.path.remove(current_dir)

from pesp4.IKESUL import *
import sys, time
from learning.StatePrefixEqOracleFailSafe import StatePrefixOracleFailSafe
from learning.FailSafeCacheSUL import FailSafeCacheSUL, print_error_info
from learning.Lstar import ju_run_Lstar
from aalpy.utils import visualize_automaton
from pesp4.IKESUL import *
import simplifyDot
import shutil,json
import pickle
import utils,logging
import argparse
import DBhelper
import random
import data_generate.utils


parser = argparse.ArgumentParser(description="Process some configuration.")

# 添加配置文件参数
parser.add_argument('config', type=str, help='The path to the configuration file.')

# 解析命令行参数
args = parser.parse_args()

config_file = args.config
# config_file = r"data_generate/strongswan_v1.json"
with open(config_file,'r',encoding='utf-8') as f:
    config = json.loads(f.read())

utils.config_vaild(config)

IKE_version = config['version']
local_ip = config['local_ip']
remote_ip = config['remote_ip']
iface = config['iface']
out_dir = os.path.join('data_generate','results', config['out_dir']) 
# out_dir = config['out_dir']
psk = config['psk']
ipsec_config = config['IPSEC_CONFIG']
auth_mode = enums.AuthMethod.RSA if ('auth_mode' in config) and (config['auth_mode'] == 'cert') else enums.AuthMethod.PSK
cert_file = config['cert_file'] if 'cert_file' in config else None
cert_passwd = config['cert_passwd'] if 'cert_passwd' in config else None
implementation = config['implementation'] if 'implementation' in config else None

if not os.path.exists(out_dir):
    # shutil.rmtree(out_dir)
    os.makedirs(out_dir)

utils.init_log(f'{out_dir}/logger.txt')
log_file_path = os.path.join(out_dir,"logger.txt")
filter_log_file_path = os.path.join(out_dir,"filter_logger.txt")
print(f'log file : {log_file_path}')
print(f'filter log file : {filter_log_file_path}')
logger = logging.getLogger(__name__)

# 启动过滤进程，传入参数
input_log_file = log_file_path

filter_keyword = utils.keyword
filter_interval = 2  # 每隔2秒过滤一次

process = Process(target=start_filtering, args=(log_file_path, filter_log_file_path, filter_keyword, filter_interval))
process.start()


if 'cmd' in config:
    for ecmd in config['cmd']:
        os.system(ecmd)   
        logger.info(utils.logger_str(f'exec cmd before run: {ecmd}'))


restart = False
if 'restart' in config:
    if config['restart'] == "True":
        restart = True
wait_time = 0
if 'wait_time' in config:
    wait_time = config['wait_time']

alphabet = None
if 'alphabet' in config:
    alphabet = config['alphabet']

must_query_result = None
if 'must_query_result' in config:
    must_query_result = config['must_query_result']
    # print(alphabet_map)
    # print(f"alphabet_map: {alphabet_map}")

    logger.info(utils.logger_str(f"must_query_result: {must_query_result}"))

alphabet_map = None
if 'alphabet_map' in config:
    alphabet_map = config['alphabet_map']
    # print(alphabet_map)
    # print(f"alphabet_map: {alphabet_map}")
    logger.info(utils.logger_str(f"alphabet_map: {alphabet_map}"))

timeout = 0.5
if 'timeout' in config:
    timeout = config['timeout']






logger.info(utils.logger_str("IKE_version: " + IKE_version + "\nlocal_ip: " + local_ip + "\nremote_ip: " + remote_ip + "\niface: " + iface + "\nout_dir: " + out_dir + "\npsk: " + psk))
logger.info(utils.logger_str(f"ipsec_config: {ipsec_config}"))
logger.info(utils.logger_str(f'alphabet: {alphabet}'))
# print(f'alphabet: {alphabet}')



ike_sul = IKESUL(local_ip, remote_ip, iface, ipsec_config,impl=implementation, version=IKE_version, dir=out_dir, psk=psk,alphabet_map = alphabet_map,must_query_result = must_query_result,restart = restart,wait_time = wait_time, auth_mode=auth_mode, cert_file=cert_file, cert_passwd=cert_passwd,timeout = timeout)


# SSH 连接信息
remote_host = "192.168.11.4"  # 替换为目标主机 IP
username = "root"  # 替换为目标主机用户名
password = "zdl"  # 替换为目标主机密码

# 建立 SSH 连接
ssh = data_generate.utils.ssh_connect(remote_host, username, password)
if not ssh:
    logging.error("ssh connect failed!")
    exit(1)

# 示例：解析 graph.dot 文件，查找从 s0 到 s1 的最短路径
dot_file = "cache/strongswan_v1/learned_model.dot"
start_node = "s0"
graph = nx.DiGraph(nx.nx_pydot.read_dot(dot_file))
nodes = list(graph.nodes())
nodes.remove('__start0')

per_state_samples = 10000
max_len = 20
for idx in range(1,per_state_samples+1):
    for target_node in nodes:
        data_out_dir = os.path.join(out_dir,target_node)
        if not os.path.exists(data_out_dir):
            os.makedirs(data_out_dir)

        logging.info(utils.logger_str(f"node : {target_node}, index : {idx}"))
        data_out_path = os.path.join(data_out_dir,f"{target_node}_{idx}.png")
        if os.path.exists(data_out_path):
            continue
        random_path = data_generate.utils.generate_random_path(graph, start_node, target_node, max_len)
        inputs, outputs = data_generate.utils.get_io(random_path)
        # print(inputs)
        # print(outputs)
        response = ike_sul.query(inputs)
        # print(response)
        if response != outputs:
            logging.error("response != outputs!!!!")
            exit(1)
        
        data_generate.utils.get_heap_mem(ssh, data_out_path)

        







process.terminate()

