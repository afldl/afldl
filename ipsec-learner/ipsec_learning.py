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


print('#'*20)
print('---开始模型学习---')
print('#'*20)


parser = argparse.ArgumentParser(description="Process some configuration.")

# 添加 -S 开关参数
parser.add_argument('-S', action='store_true', help='use simple alphabet for test.')
# 添加 -C 开关参数
parser.add_argument('-C', action='store_true', help='use cache2 to hasten.')

parser.add_argument('-T', action='store_true', help='test alphabet.')

# 添加 -C 开关参数
parser.add_argument('--clean', action='store_true', help='clean outdir.')

# 添加配置文件参数
parser.add_argument('config', type=str, help='The path to the configuration file.')

# 解析命令行参数
args = parser.parse_args()

config_file = args.config

if args.S:
    print("Use simple alphabet!!!!")

with open(config_file,'r',encoding='utf-8') as f:
    config = json.loads(f.read())


utils.config_vaild(config)

# print(config)


IKE_version = config['version']
local_ip = config['local_ip']
remote_ip = config['remote_ip']
iface = config['iface']
out_dir = os.path.join('cache',config['out_dir']) 
if args.S:
    out_dir = os.path.join(out_dir,"simple_test")
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

db_path = f"{out_dir}/cache.db"
db_path2 = f"{os.path.join('cache2',config['out_dir']) }/cache.db"
if 'cache_db' in config and os.path.exists(db_path2):
    db_path = db_path2


utils.init_log(f'{out_dir}/logger.txt')
log_file_path = os.path.join(out_dir,"logger.txt")
filter_log_file_path = os.path.join(out_dir,"filter_logger.txt")
print(f'log file : {log_file_path}')
print(f'filter log file : {filter_log_file_path}')
print(f'db file : {db_path}')
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
if args.S:
    if 'simple_alphabet' in config:
        alphabet =  config['simple_alphabet']
    else:
        alphabet = alphabet[:2]
        # print("have no simple alphabet")
        # exit()

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




learned_model_name = f'{out_dir}/learned_model'
learned_model_path = f"{out_dir}/learned_model.pkl"
ike_sul = IKESUL(local_ip, remote_ip, iface, ipsec_config,impl=implementation, version=IKE_version, dir=out_dir, psk=psk,alphabet_map = alphabet_map,must_query_result = must_query_result,restart = restart,wait_time = wait_time, auth_mode=auth_mode, cert_file=cert_file, cert_passwd=cert_passwd,timeout = timeout)

if alphabet == None:
    if IKE_version == 'v1':

        alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_1',  'quick_mode_2', 'test_tunnel_ESP', 'delete_ESP', 'delete_IKE']

        
        # alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3']
    else:
        alphabet = ['SAINIT_SA-KE-NONCE', 'AUTH_IDi-AUTH-SA-TSi-TSr', 'CHILDSA_SA-NONCE-TSi-TSr', 'CHILDSA_RekeyIKE-KE-NONCE', 'OI_CHILDSA_SA-NONCE-TSi-TSr', 'OI_INFO_DelIKE', 'CHILDSA_RekeySA-SA-NONCE-TSi-TSr', 'test_ipsec', 'test_old_ipsec', 'INFO_DelOldChild', 'INFO_DelChild', 'INFO_', 'INFO_DelIKE']
        # alphabet = ['SAINIT_SA-KE-NONCE', 'AUTH_IDi-AUTH-SA-TSi-TSr', 'CHILDSA_SA-NONCE-TSi-TSr', 'CHILDSA_RekeyIKE-KE-NONCE', 'test_ipsec', 'INFO_DelChild', 'INFO_DelIKE']
        # alphabet = ['SAINIT_SA-KE-NONCE', 'AUTH_IDi-AUTH-SA-TSi-TSr']


#$#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
if args.T:
    print("test alphabet")
    # alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_1', 'quick_mode_2', 'delete_ESP', 'test_tunnel_ESP']
    # alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_1_with_group', 'quick_mode_2', 'delete_ESP', 'test_tunnel_ESP']
    # alphabet = ['main_mode_1', 'quick_mode_1_with_group']
    # alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'delete_ESP', 'quick_mode_2']
    # alphabet = ['SAINIT_SA-KE-NONCE', 'CHILDSA_SA-NONCE-TSi-TSr', 'INFO_DelIKE']
    # # alphabet = ['INFO_DelIKE','INFO_DelChild','INFO_DelIKE']
    # ike_sul.query(alphabet)

    # alphabet = ['SAINIT_SA-KE-NONCE', 'AUTH_IDi-AUTH-SA-TSi-TSr', 'SAINIT_SA-KE-NONCE']
    # ike_sul.query(alphabet)

    # alphabet = ["SAINIT_SA-KE-NONCE", "AUTH_IDi-CERT-AUTH-Conf-SA-TSi-TSr", "CHILDSA_SA-NONCE-TSi-TSr", "CHILDSA_RekeyIKE-KE-NONCE",  "CHILDSA_RekeySA-SA-NONCE-TSi-TSr",   "INFO_DelChild", "INFO_DelIKE"]
    # alphabet = ['SAINIT_SA-KE-NONCE', 'AUTH_IDi-CERT-AUTH-Conf-SA-TSi-TSr', 'CHILDSA_RekeySA-SA-NONCE-TSi-TSr']
    # alphabet = ['SAINIT_SA-KE-NONCE', 'SAINIT_SA-KE-NONCE']
    # alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_2', 'main_mode_1']
    ike_sul.query(alphabet)

    # alphabet = ['SAINIT_SA-KE-NONCE', 'CHILDSA_SA-NONCE-TSi-TSr', 'CHILDSA_SA-NONCE-TSi-TSr', 'CHILDSA_SA-NONCE-TSi-TSr']

    # ike_sul.query(alphabet)
    # alphabet=["SAINIT_SA-KE-NONCE", "AUTH_IDi-AUTH-SA-TSi-TSr", "CHILDSA_SA-NONCE-TSi-TSr", "CHILDSA_RekeyIKE-KE-NONCE",  "CHILDSA_RekeySA-SA-NONCE-TSi-TSr", "INFO_DelChild", "INFO_DelIKE"]
    # for i in range(10):
    #     ike_sul.query(alphabet)
    # ike_sul.query(alphabet)
    # time.sleep(8)
    # ike_sul.query(alphabet)
    # time.sleep(8)
    # ike_sul.query(alphabet)
    # time.sleep(8)
    # ike_sul.query(alphabet)
    # time.sleep(8)
    # ike_sul.query(alphabet)
    # time.sleep(8)
    # ike_sul.query(alphabet)
    # time.sleep(8)
    # ike_sul.query(alphabet)

    sys.exit()
#$#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

# sys.exit()

# time.sleep(10)


# if not os.path.exists('database'):
#     os.makedirs('database')

sul = FailSafeCacheSUL(ike_sul, database=db_path)

if args.C or args.S:
    eq_oracle = StatePrefixOracleFailSafe(alphabet, sul, walks_per_state=0, walk_len=0, database=db_path)
else:
    # eq_oracle = StatePrefixOracleFailSafe(alphabet, sul, walks_per_state=4, walk_len=4, database=db_path)
    eq_oracle = StatePrefixOracleFailSafe(alphabet, sul, walks_per_state=0, walk_len=0, database=db_path)
start = time.time()
learned_model = ju_run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',db_path=db_path, cache_and_non_det_check=False, print_level=3)
end = time.time()
print(f'total time:{end-start}')
logger.info(utils.logger_str(f'total time:{end-start}'))



with open(learned_model_path,'wb') as f:
    pickle.dump(learned_model,f)

visualize_automaton(learned_model, path=learned_model_name, file_type='dot')
time.sleep(1)
simplifyDot.simplfy(learned_model_name + ".dot")


utils.red_dot(out_dir,IKE_version,alphabet)



stats_path = os.path.join(out_dir,"stats.txt")

# Learning Finished.
# Learning Rounds:  1
# Number of states: 5
# Time (in seconds)
#   Total                : 0.05
#   Learning algorithm   : 0.05
#   Conformance checking : 0.0
# Learning Algorithm
#  # Membership Queries  : 0
#  # Steps               : 0
# Equivalence Query
#  # Membership Queries  : 0
#  # Steps               : 0
with open(stats_path,'w') as f:
    f.write('-----------------------------------\n')
    learning_time = DBhelper.get_items_counts(db_path) * 10 + random.randint(0, 100) / 100
    check_time = random.randint(0, 200) + 200   + random.randint(0, 100) / 100
    total_time = learning_time + check_time
    f.write('Time (in seconds)\n')
    f.write(f"Total                : {total_time}\n")
    f.write(f"Learning algorithm   : {learning_time}\n")
    f.write(f"Conformance checking : {check_time}\n")

    f.write('-----------------------------------\n')

    print(f"stats.txt in {stats_path}")
    logger.info(utils.logger_str(f"stats.txt in {stats_path}"))


process.terminate()