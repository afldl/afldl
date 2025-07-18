import sys, time, argparse, signal
from learning.StatePrefixEqOracleFailSafe import StatePrefixOracleFailSafe
from learning.FailSafeCacheSUL import FailSafeCacheSUL, print_error_info
from learning.Lstar import ju_run_Lstar
from aalpy.utils import visualize_automaton
from SSH.SSHSUL import *
import simplifyDot
import shutil


def start_mapper_process(mapper_path, target_ip, target_port, username, password):
    mapperProcess = subprocess.Popen(["python2", mapper_path, target_ip, target_port, username, password], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # mapperProcess = subprocess.Popen(["python2", mapper_path, target_ip, target_port, username, password])
    time.sleep(1)
    print(f"mapper_pid:{mapperProcess.pid}")
    return mapperProcess.pid


def model_learning(mapper_ip, mapper_port, out_dir, simple_test:bool=False):
    
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)
        
    learned_model_name = f'{out_dir}/learned_model'
    
    ssh_sul = SSHSUL(ip=mapper_ip, port=mapper_port)
    try:
        ssh_sul.connect()
        print('Successfully connect to mapper')
    except Exception as e:
        print(f'Tcp connect failed: {e}')
        sys.exit()
        
    alphabet = ['KEXINIT', 'KEX30', 'NEWKEYS', 'SR_AUTH', 'UA_PW_OK', 'CH_OPEN']
    if simple_test:
        print('Trying simple test')
        ssh_sul.query(alphabet)
        ssh_sul.disconnect()
        return 

    if not os.path.exists('database'):
        os.makedirs('database')

    sul = FailSafeCacheSUL(ssh_sul, database=f'database/{out_dir}.db')
    eq_oracle = StatePrefixOracleFailSafe(alphabet, sul, walks_per_state=20, walk_len=10, database=f'database/{out_dir}.db')
    
    start = time.time()
    learned_model = ju_run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',db_path=f'database/{out_dir}.db', cache_and_non_det_check=False, print_level=3)
    end = time.time()
    print(f'total time:{end-start}')
    ssh_sul.disconnect()
    
    visualize_automaton(learned_model, path=learned_model_name, file_type='dot')
    time.sleep(1)
    simplifyDot.simplfy(learned_model_name + ".dot")
        
def clean_process_by_pid(pid):
    try:
        os.kill(pid, signal.SIGTERM)
        print("Mapper Process terminated.")
    except OSError as e:
        print("Failed to kill process:", str(e))
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mapper_path', default='./ssh_learner/mapper.py', help='mapper path (default: mapper.py)')
    parser.add_argument('-I', dest='mapper_ip', default='127.0.0.1', help='mapper ip (default: 127.0.0.1)')
    parser.add_argument('-T', dest='mapper_port', default='8643', help='mapper port (default: 8643)')
    parser.add_argument('-i', dest='server_ip', default='127.0.0.1', help='server ip (default: 127.0.0.1)')
    parser.add_argument('-t', dest='server_port', default='22', help='server port (default: 22)')
    parser.add_argument('-n', dest='username', default='root', help='username (default: root)')
    parser.add_argument('-p', dest='password', default='123456', help='password (default: 123456)')
    parser.add_argument('-o', dest='out_dir', default='./ssh_learning', help='out dir (default: ssh_learning)')
    args = parser.parse_args()
    
    mapper_pid = start_mapper_process(args.mapper_path, args.server_ip, args.server_port, args.username, args.password)
    model_learning(args.mapper_ip, args.mapper_port, args.out_dir, simple_test=False)
    clean_process_by_pid(mapper_pid)