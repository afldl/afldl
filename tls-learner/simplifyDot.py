import os
import argparse

def abstract_symbol_to_more_abstract_symbol_v1(symbol:str, is_request:bool):
    if symbol == 'No_response':
        result = None
    input_alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_1',  'quick_mode_2', 'test_tunnel_esp', 'delete_esp', 'delete_ike', 'aggressive_mode_1', 'aggressive_mode_2', 'new_group', 'multi_sa_main_mode_1', 'wrong_nonce_main_mode_2', 'wrong_order_quick_mode_1']
    output_alphabet = ['main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_1', 'esp_reply', 'wrong_esp_reply', 'delete_esp', 'delete_ike', 'aggressive_mode_1', 'multi_sa_main_mode_1', 'plain_main_mode_3']
    symbol = symbol.lower()
    symbol = symbol.replace('*', '')
    if is_request:
        result = f'{symbol}_req' if symbol in input_alphabet else 'other_req'
    else:
        tokens = symbol.split('-')
        result = ''
        for t in tokens:
            result += f'{t}_resp-' if t in output_alphabet else 'other_resp-'
        result = result.strip('-')
    return result
    
def abstract_symbol_to_more_abstract_symbol_v2(symbol:str, is_request:bool):
    result = None
    others = ['DecryptedError', 'PortUnreachable', 'None']
    if symbol == 'No_response':
        return 'no_response'
    elif symbol in others:
        result = symbol
    elif symbol == 'Plain_response':
        result = 'plain_resp'
    elif 'test_ipsec' in symbol:
        return 'ipsec_req'
    elif 'test_old_ipsec' in symbol:
        return 'old_ipsec_req'
    elif 'Replay' in symbol:
        result = 'ipsec_resp' if 'misMatch' not in symbol else 'ipsec_mismatch_resp'
        return result
    else:
        result = ''
        if 'OI_' in symbol:
            result += 'old_'
            symbol = symbol.split('OI_')[1]
        ex_type = symbol.split('_')[0]
        pds = symbol.split('_')[1]
        if ex_type == 'SAINIT':
            if 'SA' in pds and 'KE' in pds and 'NONCE' in pds:
                result += 'init'
            else:
                result += 'wrong_init'
        elif ex_type == 'AUTH':
            if 'AUTH*' in pds:
                result += 'wrong_auth'
            elif 'AUTH' in pds:
                result += 'auth'
            elif '18' in pds:
                result += 'auth_fail'
        elif ex_type == 'CHILDSA':
            if 'RekeyIKE' in pds:
                if 'KE' in pds and 'NONCE' in pds:
                    result += 'rekey_ike'
                else:
                    result += 'wrong_rekey_ike'
            elif 'RekeySA' in pds:
                result += 'rekey_child_sa'
            elif 'SA' in pds and 'NONCE' in pds:
                result += 'create_child' if 'TransMode' not in pds else 'create_child_transmode'
        elif ex_type == 'INFO':
            if 'DelIKE' in pds:
                result += 'del_ike'
            elif 'DelChild' in pds or 'DELETE' in pds:
                result += 'del_child'
        if result is None:
            result = 'other'
        else:
            result += '_req' if is_request else '_resp'
    return result

def abstract(symbol:str, is_request:bool, version):
    if version not in ['v1', 'v2']:
        raise Exception('Invalid IKE version: {}'.format(version))
    if version == 'v1':
        return abstract_symbol_to_more_abstract_symbol_v1(symbol, is_request)
    elif version == 'v2':
        return abstract_symbol_to_more_abstract_symbol_v2(symbol, is_request)
    
def alphabet_transform(lines:str, ike_version = 'v1'):
    if ike_version not in ['v1', 'v2']:
        raise Exception('Invalid IKE version: {}'.format(ike_version))
    
    inps_map = {}
    outs_map = {}
    new_lines = []
    for line in lines:
        if '->' in line and '/' in line:    # which means this line is a state transition, like "s0 -> s1  [label="main_mode_1/main_mode_1"];"
            inp_out = line.split('label="')[1].split('"]')[0]
            inp = inp_out.split('/')[0]
            out = inp_out.split('/')[1]
            if inp not in inps_map.keys():
                inps_map[inp] = abstract(inp, True, ike_version)
            if out not in outs_map.keys():
                outs_map[out] = abstract(out, False, ike_version)
            new_line = line.split('/')[0].replace(inp, inps_map[inp]) + '/' + line.split('/')[1].replace(out, outs_map[out])
            new_lines.append(new_line)
        else:
            new_lines.append(line)
    
    return new_lines
                 
def simplfy(dot_file:str, ike_version=None):
    with open(dot_file, "r") as f:
        data = f.readlines()
    
    lines = alphabet_transform(data, ike_version) if ike_version else data

    dot = ''
    transs = []
    for line in lines:
        if 'digraph' in line:
            dot += f'{line}splines="line";\n'
        elif ('->' not in line) or ('start' in line):
            dot += line
        else:
            trans = line.split('[')[0]
            if trans in transs:
                continue
            transs.append(trans)
            new_line = trans + '[label="'
            for l in lines:
                if trans in l:
                    new_line += (l.split('label="')[1].split('"]')[0] + '\n')
            new_line += '"];\n'
            dot += new_line
    
    with open(dot_file.split('.dot')[0] + "_smv.dot", "w+") as f:
        [f.write(l) for l in lines] 
        
    with open(dot_file.split('.dot')[0] + "_simplfy.dot", "w+") as f:
        f.write(dot)
                
def remove_start(dot_file):
    fi = open(dot_file, 'r')
    lines = fi.readlines()
    fi.close()
    
    os.remove(dot_file)
    fo = open(dot_file, 'w+')
    for line in lines:
        if 'start' in line:
            continue
        fo.write(line)
    fo.close()
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('-i','--dot_file',default=None,type=str,required=True)
    parser.add_argument('-v','--ike_version',default=None,type=str,required=False)
    args = parser.parse_args()
    simplfy(args.dot_file, args.ike_version)
