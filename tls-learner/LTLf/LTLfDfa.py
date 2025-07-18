from ltlf2dfa.parser.ltlf import *
from aalpy.automata import Dfa, DfaState
from aalpy.base.Automaton import *
from aalpy.utils.AutomatonGenerators import *
from aalpy.utils.HelperFunctions import *
from aalpy.utils.FileHandler import *
from aalpy.utils.FileHandler import _strip_label, _process_node_label, _process_label
from pydot import graph_from_dot_data
from LTLf.IPsecLTLfFormulas import *
from LTLf.TLS13LTLfFormulas import *
import re, hashlib, math
import constant as constant
from typing import List, Dict
import xml.etree.ElementTree as ET
import xml.dom.minidom

def str2list(lstr: str) -> list:
    """Convert a list string to real list."""
    lstr = lstr.strip('[]')
    lst = [out.strip("''") for out in lstr.split(', ')]
    return lst

def hash(string):
    hash_obj = hashlib.md5()
    hash_obj.update(string.encode('utf-8'))
    return hash_obj.hexdigest()

def is_prefix_list(lst1, lst2):
    if len(lst1) > len(lst2):
        return False
    return lst1 == lst2[:len(lst1)]

def mona_dfa_to_aalpy_dfa(data=None, path=None, topath=None):
    """convert a mona DFA to AALPY DFA

    Args:
        data : dot data that describe a mona DFA.
        path : mona DFA dot file path.
        topath : file path to save the AALPY DFA dot data.

    Returns:
        str: the AALPY DFA dot data.
    """
    if data is None and path is None:
        print('Please provide graph data or file path!')
        return
    if path is not None:
        with open(path, 'r') as f:
            data = f.read()
    lines = data.split('\n')
    new_lines = 'digraph DFA {\n'
    nodes = []
    accept_nodes = []
    
    delete = []
    for line in lines:
        if 'init [' in line or 'init ->' in line:
            delete.append(line)
    [lines.remove(line) for line in delete]
            
    for line in lines:
        if '->' in line:
            node = line.split('->')[0].strip(' ')
            if node not in nodes:
                nodes.append(node)
        elif 'doublecircle' in line:
            accept_nodes = line.split('];')[1].split('; ')
            accept_nodes = [i.strip(' ;') for i in accept_nodes]
    
    for node in nodes:
        if node in accept_nodes:
            new_lines += f' s{node} [label="s{node}", shape=doublecircle];\n'
        else:
            new_lines += f' s{node} [label="s{node}"];\n'
    
    for line in lines:
        if '->' in line:
            first = line.split('->')[0].strip(' ')
            second = line.split(' [')[0].split('-> ')[1]
            new_line = f' s{first} -> s{second} [{line.split(" [")[1]}\n'
            new_lines += new_line
    
    new_lines += ' __start0 [label="", shape=none];\n'  
    new_lines += ' __start0 -> s1  [label=""];\n'  
    new_lines += '}\n'
    if topath is not None:
        with open(topath, 'w') as f:
            f.write(new_lines)
    return new_lines
           
def load_automaton_from_data(data, automaton_type, compute_prefixes=False):
    """copy from AALPY
    """
    graph = graph_from_dot_data(data)[0]

    assert automaton_type in automaton_types.values()

    id_node_aut_map = {'dfa': (DfaState, Dfa), 'mealy': (MealyState, MealyMachine), 'moore': (MooreState, MooreMachine),
                       'onfsm': (OnfsmState, Onfsm), 'mdp': (MdpState, Mdp), 'mc': (McState, MarkovChain),
                       'smm': (StochasticMealyState, StochasticMealyMachine)}

    nodeType, aut_type = id_node_aut_map[automaton_type]

    node_label_dict = dict()
    for n in graph.get_node_list():
        if n.get_name() == '__start0' or n.get_name() == '' or n.get_name() == '"\\n"':
            continue
        label = None
        if 'label' in n.get_attributes().keys():
            label = n.get_attributes()['label']
            label = _strip_label(label)

        _process_node_label(n, label, node_label_dict, nodeType, automaton_type)

    initial_node = None
    for edge in graph.get_edge_list():
        if edge.get_source() == '__start0':
            initial_node = node_label_dict[edge.get_destination()]
            continue

        source = node_label_dict[edge.get_source()]
        destination = node_label_dict[edge.get_destination()]

        label = edge.get_attributes()['label']
        label = _strip_label(label)
        _process_label(label, source, destination, automaton_type)

    if initial_node is None:
        print("No initial state found. \n"
              "Please follow syntax found at: https://github.com/DES-Lab/AALpy/wiki/"
              "Loading,Saving,-Syntax-and-Visualization-of-Automata ")
        assert False

    automaton = aut_type(initial_node, list(node_label_dict.values()))
    if automaton_type != 'mc' and not automaton.is_input_complete():
        print('Warning: Loaded automaton is not input complete.')
    if compute_prefixes and not automaton_type == 'mc':
        for state in automaton.states:
            state.prefix = automaton.get_shortest_path(automaton.initial_state, state)
    return automaton

def get_last_left_event(left_part:str):
    left_part = left_part.strip(' ')
    if left_part[-1] == ')':
        pattern = r'\((.*?)\)$'
        match = re.findall(pattern, left_part)
        left_event = f'({match[-1]})'
    else:
        left_event = re.findall(r'~?\w+', left_part)[-1]
    return left_event

def get_first_right_event(right_part:str):
    right_part = right_part.strip(' ')
    if right_part[0] == '(':
        pattern = r'\((.*?)\)$'
        match = re.findall(pattern, right_part)
        right_event = f'({match[0]})'
    else:
        right_event = re.findall(r'~?\w+', right_part)[0]
    return right_event
    
def split_transition_label(input_str:str, result:list):
    if '|' in input_str:
        first_pipe_index = input_str.find("|")
        left_part = input_str[:first_pipe_index]
        right_part = input_str[first_pipe_index + 1:]
        left_event = get_last_left_event(left_part)
        right_event = get_first_right_event(right_part)
        event1 = input_str.replace(f' | {right_event}', '')
        event2 = input_str.replace(f'{left_event} | ', '')
        split_transition_label(event1, result)
        split_transition_label(event2, result)
    else:
        events = input_str.split(' & ')
        positive = [e.strip('()') for e in events if '~' not in e]
        if len(positive) == 0:
            result.append('\u03BC')
        elif len(positive) == 1:
            result.append(positive[0])
    
def simplify_transitions(dfa:Dfa):
    """simplify a AALPY DFA based on the mutual exclusion of atomic propositions in LTLf.

    Args:
        dfa (Dfa): a AALPY DFA
    """
    state_to_remove = []
    for state in dfa.states:
        new_transitions = dict()
        for key in state.transitions.keys():
            new_keys = []
            split_transition_label(key, new_keys)
            new_keys = list(set(new_keys))
            for new_key in new_keys:
                new_transitions[new_key] = state.transitions[key]
        state.transitions = new_transitions
        if dfa.get_shortest_path(dfa.initial_state, state) is None:
            state_to_remove.append(state)
    for state in state_to_remove:
        dfa.states.remove(state)
    return dfa
            
def ltl_formula_to_ltl_dfa(formula_name: str, formula_str: str):
    """Convert an LTLf formula to an LTLfDfa.

    Args:
        formula_name (str): A name used to identify the LTLf formula.
        formula_str (str): the whole LTLf formula corresponding to the formula name.

    Returns:
        ltldfa: An instance of the LTLfDfa class.
    """
    parser = LTLfParser()
    formula = parser(formula_str)
    formula = formula.negate()
    mona_dfa_dot = formula.to_dfa()
    dfa_dot = mona_dfa_to_aalpy_dfa(data=mona_dfa_dot)
    dfa = load_automaton_from_data(dfa_dot, 'dfa')
    dfa = simplify_transitions(dfa)
    ltldfa = LTLfDfa(formula_name, formula_str, dfa.initial_state, dfa.states)
    return ltldfa

def ltl_formula_to_dfa(formula_name: str, formula_str: str):
    """Convert an LTLf formula to an Dfa.

    Args:
        formula_name (str): A name used to identify the LTLf formula.
        formula_str (str): the whole LTLf formula corresponding to the formula name.

    Returns:
        dfa: An instance of the Dfa class.
    """
    parser = LTLfParser()
    formula = parser(formula_str)
    formula = formula.negate()
    mona_dfa_dot = formula.to_dfa()
    dfa_dot = mona_dfa_to_aalpy_dfa(data=mona_dfa_dot)
    dfa = load_automaton_from_data(dfa_dot, 'dfa')
    dfa = simplify_transitions(dfa)
    dfa.visualize(formula_name, 'dot')
    return dfa

class Seed():
    """
    A interesting testcase for a specific DFA.
    """
    
    def __init__(self, name:str, inputs:list, state_path:list, distance):
        """
        Args:

            name (str): the prefix name of file to save this seed 
            inputs (list) : the input sequence generated during fuzzing
            state_path (list) : the state path corresponding to symbol path
            distance : the distance from the last state in state_path to the accepted state(s) in this DFA
        """
        self.name = name
        self.inputs = inputs[:]
        self.state_path = state_path[:]
        self.distance = distance
        
        self.selected_time = 0
        self.found_seed_count = 0
        self.found_cex_count = 0
        self.initial_score = self.compute_initial_score()
        self.score = self.initial_score
    
    def compute_initial_score(self):
        res = (len(self.state_path) / (len(self.state_path)+self.distance)) + 1/len(self.inputs)
        return res
        
    def compute_score(self):
        self.score = self.initial_score * (self.found_seed_count+self.found_cex_count*constant.CEX_WEIGHT+1) / (math.log(self.selected_time+1)+1)
        return self.score
    
    def compute_energy(self):
        return int(self.compute_score() * 10)

   
class LTLfDfa(Dfa):
    """
    Deterministic finite automaton which describes one LTLf(Linear Temporal Logic on Finite Traces) formula.
    """
    
    def __init__(self, formula_name: str, formula:str, initial_state: DfaState, states):
        """

        Args:
            formula_name (str): A name used to identify the LTLf formula.
            formula (str): the whole LTLf formula corresponding to the formula name.
            initial_state (DfaState): initial state of the DFA.
            states :  list containing all states of the DFA.
        """
        super().__init__(initial_state, states)
        self.formula_name = formula_name
        self.formula = formula
        self.alphabet = self.get_input_alphabet()
        self.accepted_states = self.get_accepted_state()
        
        self.visited_state = dict()
        self.crash_count = 0
        self.ltl_violation_count = 0
        self.state_path = [] 
        self.seeds_pool :Dict[str, Seed] = {}
        self.current_seed = None
        self.fuzzs = 0
        self.selected_times = 0
        self.score = 1
    
    def compute_score(self):
        if self.ltl_violation_count >= constant.MAX_CEX_COUNT:
            self.score = 0
        else:
            self.score = math.ceil(1000 * pow(2, -math.log10(math.log10(self.fuzzs + 1) * self.selected_times + 1)) 
                          * pow(2, math.log(len(self.seeds_pool)+(self.crash_count+self.ltl_violation_count)*constant.CEX_WEIGHT+1)))
        return self.score
    
    def reset(self):
        """
        Reset before each testcase execution. state_path maintains the state trace generated during execution.
        """
        self.reset_to_initial()
        self.state_path = []
        
    def get_accepted_state(self) -> list:
        accepted_states = [state for state in self.states if state.is_accepting]
        return accepted_states

    def get_all_no_loop_path(self, origin_state: DfaState, target_state: DfaState) -> Union[list, None]:
        """Find all no loop paths from origin state to target state.

        Returns:
            Union[list, None]: the paths list or None
        """
        if origin_state not in self.states or target_state not in self.states:
            warnings.warn('Origin or target state not in automaton. Returning empty path.')
            return None

        all_paths = []
        queue = [[origin_state]]

        if origin_state == target_state:
            return None

        while queue:
            path = queue.pop(0)
            node = path[-1]
            neighbours = node.transitions.values()
            for neighbour in neighbours:
                if neighbour in path[:-1]:
                    continue
                new_path = list(path)
                new_path.append(neighbour)
                queue.append(new_path)
                # return path if neighbour is goal
                if neighbour == target_state:
                    acc_seq = new_path[:-1]
                    inputs = []
                    for ind, state in enumerate(acc_seq):
                        inputs.append(next(key for key, value in state.transitions.items()
                                           if value == new_path[ind + 1]))
                    all_paths.append(inputs)

        return all_paths
         
    def step_based_on_inp_out(self, inp: str, outs: List[str]):
        """The DFA performs state transitions based on input and outputs.
           First, for an input or output symbol not in the alphabet of the DFA, we replace it with 'other'(_req or _resp).
           If 'true' in the state transitions keys, just performs 'true'.
           If the symbol not in state transitions keys, we replace it with '\u03BC' and perform it. 

        Args:
            inp (str): input sent to the SUT.
            outs (List[str]): output(s) from the SUT after receiving the input.
        """
        if inp not in self.alphabet:
            inp = 'other_inp'
        if 'true' in self.current_state.transitions.keys():
            self.current_state = self.current_state.transitions['true']
        else:
            inp = '\u03BC' if inp not in self.current_state.transitions.keys() else inp
            self.current_state = self.current_state.transitions[inp]
        self.state_path.append(self.current_state.state_id)
        
        for out in outs:
            print(outs)
            if out not in self.alphabet:
                out = 'other_out'
            if 'true' in self.current_state.transitions.keys():
                self.current_state = self.current_state.transitions['true']
            else:
                out = '\u03BC' if out not in self.current_state.transitions.keys() else out
                self.current_state = self.current_state.transitions[out]
            self.state_path.append(self.current_state.state_id)
            
    def ltl_to_sut_map(self, symbol_name):
        if self.formula in TLS13_formulas.values():
            return tls_ltl_to_sut_map(symbol_name)
        else:
            raise Exception
    
    def get_all_path_to_target_state(self, target_state: DfaState) -> Union[list, None]:
        """Find all reachable paths from current state to target state. 
           If one path start with a 'resp' which represents a response message,
           we think it an unreachable path.

        Returns:
            Union[list, None]: all reachable paths from current state to target state, or None.
        """
        paths = self.get_all_no_loop_path(self.current_state, target_state)
        # print(paths)
        if paths is None:
            return None
        reachable_paths = [path for path in paths if self.ltl_to_sut_map(path[0]).is_input]
        return reachable_paths if reachable_paths else None    
    
    def get_distance_to_target_state(self, target_state: DfaState):
        """
        Compute distance from current state to target state:
        1. If current state is target state, return 0;
        2. If there is no path from current state to target state, return infinite.
        3. Otherwise, return the mean length of all path. 
        """
        if self.current_state.state_id == target_state.state_id:
            return 0
        paths = self.get_all_path_to_target_state(target_state)
        if paths is None:
            return float('inf')
        else:
            total_len = 0
            for path in paths:
                total_len += len(path)
            return total_len/len(paths)
        
    def get_distance_to_accept_states(self):
        """
        Compute distance from current state to accepted state(s):
        1. If current state is an accepted state, return 0;
        2. Otherwise, return the mean distance form current state to all reacheable accepted state. 
        """
        distance = 0
        reachable_count = 0
        for state in self.accepted_states:
            temp = self.get_distance_to_target_state(state)
            if temp == 0:
                return 0
            elif temp == float('inf'):
                continue
            reachable_count += 1
            distance += self.get_distance_to_target_state(state)
        return distance/reachable_count if reachable_count > 0 else float('inf')
    
    def is_interesting(self, inputs: list) -> bool:
        """Decide if the inputs is interesting. Based on the following three conditions:
           1. this sequence not in the seed pool;
           2. this sequence reaches state closer to the accepted state(s);
           3. this sequence reaches unvisited state.
        """
        if len(self.seeds_pool) >= 20:
            return False
        if len(inputs) == 0 or len(self.state_path) == 0:
            return False
        
        pure_inputs = str(inputs).replace('*', '')
        if hash(pure_inputs) in self.seeds_pool.keys():
            return False
        
        if self.current_seed is not None and self.get_distance_to_accept_states() >= self.seeds_pool[self.current_seed].distance:
            return False
        
        if self.current_state.state_id not in self.visited_state.keys():
            self.visited_state[self.current_state.state_id] = [inputs[:]]
        else:
            for seq in self.visited_state[self.current_state.state_id]:
                if is_prefix_list(seq, inputs):
                    return False
            self.visited_state[self.current_state.state_id].append(inputs[:])

        return True
        
    def found_interesting_sequence(self, inputs: list) -> bool:
        """
        If an input sequence is interesting, add it to the seed pool, and update found_seed_count of current seed.
        """
        if self.is_interesting(inputs):
            seed_count = len(self.seeds_pool) + 1
            print(f'{self.formula_name} : saving {seed_count}th seed...')
            print(self.state_path)
            file_name = f'seed-{seed_count}'
            seed = Seed(file_name, inputs, self.state_path, self.get_distance_to_accept_states())
            pure_inputs = str(inputs).replace('*', '')
            self.seeds_pool[hash(pure_inputs)] = seed
            if self.current_seed is not None:
                self.seeds_pool[self.current_seed].found_seed_count += 1
            return True
        return False
    
    def reach_accepted_state(self):
        """
        If current state is one accepted state, we think found one violation.
        """
        if self.ltl_violation_count >= constant.MAX_CEX_COUNT:
            return False
        for state in self.accepted_states:
            if self.current_state.state_id == state.state_id:
                self.ltl_violation_count += 1
                if self.current_seed is not None:
                    self.seeds_pool[self.current_seed].found_cex_count += 3
                return True
        return False
            
    def choose_seed(self) -> Seed:
        """
        Choose one seed from seed pool. Seeds with higher scores are more likely to be selected, similar to AFLNet.
        """
        if len(self.seeds_pool) == 0:
            return None
        calculate_score = 0
        for s in self.seeds_pool.values():
            calculate_score += s.compute_score()
        rand = random.randint(0, math.ceil(calculate_score))
        calculate_score = 0
        for s in self.seeds_pool.values():
            calculate_score += s.score
            if calculate_score >= rand:
                s.selected_time += 1
                return s
            
    def get_next_input(self) -> str:
        """
        The next input is selected based on the paths from the current state to the accepted state(s), 'random' selected with a certain probability.
        """
        target_state = random.choice(self.accepted_states)
        paths = self.get_all_path_to_target_state(target_state)
        if paths is None:
            return None
        if random.randint(0, 3) == 0:
            return 'random'
        shortest_path = min(paths, key=len)
        choosed_path = shortest_path if random.randint(0, 2)==0 else random.choice(paths)
        next_input = choosed_path[0]
        result = self.ltl_to_sut_map(next_input).name
        if result is None or result == 'any_inp':
            result = 'random'
        elif result == 'other_inp':
            #TODO
            result = 'random' 
        elif result == '\u03BC':
            #TODO
            result = 'random' 
        return result
    
    def save_context(self, dfa_et: ET.Element):
        ET.SubElement(dfa_et, "exections").text = str(self.fuzzs)
        ET.SubElement(dfa_et, "selected_times").text = str(self.selected_times)
        ET.SubElement(dfa_et, "crash_count").text = str(self.crash_count)
        ET.SubElement(dfa_et, "counterexample_count").text = str(self.ltl_violation_count)
        ET.SubElement(dfa_et, "score").text = str(self.score)
        for name, seed in self.seeds_pool.items():
            label = ET.SubElement(dfa_et, seed.name)
            ET.SubElement(label, "name").text = seed.name
            ET.SubElement(label, "inputs").text = str(seed.inputs)
            ET.SubElement(label, "state_path").text = str(seed.state_path)
            ET.SubElement(label, "distance").text = str(seed.distance)
            ET.SubElement(label, "initial_score").text = str(seed.initial_score)
            ET.SubElement(label, "selected_time").text = str(seed.selected_time)
            ET.SubElement(label, "found_seed_count").text = str(seed.found_seed_count)
            ET.SubElement(label, "found_cex_count").text = str(seed.found_cex_count)
    
    def resume(self, dfa_et: ET.Element):
        self.fuzzs = int(dfa_et.find('exections').text)
        self.selected_times = int(dfa_et.find('selected_times').text)
        self.crash_count = int(dfa_et.find('crash_count').text)
        self.ltl_violation_count = int(dfa_et.find('counterexample_count').text)
        self.score = float(dfa_et.find('score').text)
        seeds = dfa_et.findall('seed*')
        for seed in seeds:
            name = seed.find('name').text
            inputs = str2list(seed.find('inputs').text)
            state_path = str2list(seed.find('state_path').text)
            distance = float(seed.find('distance').text)            
            s = Seed(name, inputs, state_path, distance)
            self.seeds_pool[hash(str(inputs).replace('*', ''))] = s
            s.initial_score = float(seed.find('initial_score').text)
            s.selected_time = int(seed.find('selected_time').text)
            s.found_seed_count = int(seed.find('found_seed_count').text)
            s.found_cex_count = int(seed.find('found_cex_count').text)
            