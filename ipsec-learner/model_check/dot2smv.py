import os
import argparse

def dot2smv(dot_file:str, ltl_file:str):
    with open(dot_file, 'r') as f:
        dot = f.readlines()
        
    states = []
    inps = []
    outs = []
    state_transitions = []
    out_transitions = []
    for line in dot:
        if ('->' not in line) and ('start' not in line) and ('label' in line):
            s = line.split('[')[0].strip()
            if s not in states:
                states.append(s)
        elif ('->' in line) and ('/' in line):
            inp_out = line.split('label="')[1].split('"]')[0]
            inp = inp_out.split('/')[0]
            out = inp_out.split('/')[1]
            if inp not in inps:
                inps.append(inp)
            if out not in outs:
                outs.append(out)
            start_state = line.split('->')[0].strip()
            end_state = line.split('->')[1].split('[')[0].strip()
            state_transition = f'state = {start_state} & inp = {inp}: {end_state};\n'
            state_transitions.append(state_transition)
            out_transition = f'state = {start_state} & inp = {inp}: {out};\n'
            out_transitions.append(out_transition)

    states_str = 'VAR state : {'
    for s in states:
        states_str += f'{s},'
    states_str = states_str.strip(',')
    states_str += '};\n'
    
    inps_str = 'inp : {'
    for i in inps:
        inps_str += f'{i},'
    inps_str = inps_str.strip(',')
    inps_str += '};\n'
    
    outs_str = 'out : {'
    for o in outs:
        outs_str += f'{o},'
    outs_str = outs_str.strip(',')
    outs_str += '};\n'
    
    state_transitions_str = 'ASSIGN\ninit(state) := s0;\nnext(state) := case\n'
    for st in state_transitions:
        state_transitions_str += st
    state_transitions_str += 'esac;\n'
    
    out_transitions_str = 'out := case\n'
    for ot in out_transitions:
        out_transitions_str += ot
    out_transitions_str += 'esac;\n\n'
    
    with open(ltl_file, 'r') as f:
        ltl = f.read()
    
    module = 'MODULE main\n' + states_str + inps_str + outs_str + state_transitions_str + out_transitions_str + ltl

    smv_file = dot_file.split('.')[0] + '.smv'
    with open(smv_file, 'w+') as f:
        f.write(module)
        
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('-i','--dot_file',default=None,type=str,required=True)
    parser.add_argument('-s','--ltl_file',default=None,type=str,required=True)
    args = parser.parse_args()
    dot2smv(args.dot_file, args.ltl_file)
