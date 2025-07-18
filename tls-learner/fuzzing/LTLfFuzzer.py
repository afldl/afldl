import random
import time
import signal
from fuzzing.LTLfSUT import LTLfSUT
from fuzzing.StateChecker import *
import constant as constant

class LTLfFuzzer():
    """The fuzzing engine."""
    
    def __init__(self, formulas: dict, alphabet: list, sut: LTLfSUT, fuzzing_walk_len = 20, out_dir = None, resume = False):
        """
        Args:
            formulas (dict): the LTLf formulas provided by tester.
            alphabet (list): the set of input symbols that can be instantiated by mapper.
            sut (LTLfSUT): consists of the mapper and SUT, mainly mapper.
            fuzzing_walk_len (int, optional): the testcase length counted by inputs. Defaults to 20.
            out_dir (_type_, optional): the folder to save all useful results.
        """
        if os.path.exists(out_dir) and not resume:
            print("The dir already exists, try manually deleting it, or if you want to continue fuzz from last time, set resume = True.")
            sys.exit()
                    
        self.formulas = formulas
        self.alphabet = alphabet
        self.sut = sut
        self.fuzzing_walk_len = fuzzing_walk_len
        self.out_dir = out_dir
        
        signal.signal(signal.SIGINT, self.save_before_terminated)
        self.start_time = time.time()
        self.already_fuzz_time = 0 # The cumulative time since the last interruption
        
        self.stateChecker = StateChecker(formulas, out_dir)
        self.total_fuzz_count = 0
        self.crash_count = 0
        self.ltl_violation_count = 0
        self.inputs = []
        self.outputs = []
        
        if os.path.exists(out_dir) and resume:
            try:
                self.resume()
            except FileNotFoundError:
                print('There is no fuzz_context.xml file, can not resume fuzz process!')
                sys.exit()
        else:
            self.create_dir()
        
    def create_dir(self):
        if os.path.exists(self.out_dir):
            shutil.rmtree(self.out_dir)
        os.makedirs(self.out_dir)
        for key in self.stateChecker.DFAs.keys():
            # create one dir for each formula/DFA to save seed or violation
            dir = f'{self.out_dir}/{key}'
            if os.path.exists(dir):
                shutil.rmtree(dir)
            os.makedirs(dir)
        
    def reset_sut_and_dfa(self):
        """
        Performed berfore every fuzz exection. The inputs save all input symbols sent to SUT.
        The outputs save all output symbols responded by SUT. It's a list of list. 
        """
        self.sut.reset()
        self.stateChecker.reset_all_DFAs()
        self.inputs = []
        self.outputs = []
            
    def save_crash(self):
        """Save one testcase that triggers SUT crash. 
        We save it in three forms: symbol sequence; pcap file; plain bytes."""
        self.crash_count += 1
        self.stateChecker.DFAs[self.stateChecker.current_dfa].crash_count += 1
        print(f'saving {self.crash_count}th crash...')
        file_name = f'{self.out_dir}/crash-{self.crash_count}'
        self.save_byte_and_pcap(file_name)
        save_to_file = f'{self.inputs}\n{self.outputs}'
        with open(f'{file_name}.txt', 'w') as file:
            file.write(f'{save_to_file}')
            
    def save_byte_and_pcap(self, file_name):
        """Save the interaction messages to pcap and in plain bytes."""
        self.sut.save_pcap(file_name)
        self.sut.save_fuzz_contents(file_name)
  
    def load_fuzz_data_from_file(self, file_name):
        self.sut.read_fuzz_contents(file_name)
    
    def dfa_step(self, inp, outs, seq):
        """Perform state transtation in all DFAs."""
        # We use 'None' represents that the input not be sent.
        if 'None' in outs:
            return 
            
        # Map input/output symbols to atomic propositions in LTLf formulas.
        inp = self.sut.sut_to_ltl_map(inp, True)
        outs = [self.sut.sut_to_ltl_map(out, False) for out in outs]
        seq.extend([inp] + [out for out in outs])
        self.stateChecker.step(inp, outs)
            
    def fuzz_randomly(self):
        print('Randomly fuzzing' + '-'*50)
        print(f'current DFA: {self.stateChecker.current_dfa}')
        print(f'total fuzz count: {self.total_fuzz_count}')
        self.sut.pre()
        self.reset_sut_and_dfa()
        abstract_sequence = []
        for i in range(random.randint(1, self.fuzzing_walk_len)):
            next_symbol = self.stateChecker.get_next_input()
            
            if next_symbol is None:
                print('target state is unreachable')
                break
            elif next_symbol == 'random':
                next_symbol = random.choice(self.alphabet)
                
            # fuzz one symbol with 75% probability
            if random.randint(0, 3) > 0:
                outs = self.sut.step(next_symbol)
                fuzzed_abs = next_symbol
            else: 
                fuzzed_abs, outs = self.sut.fuzz_step(next_symbol)
            outs = outs.split('-')
            self.inputs.append(fuzzed_abs)
            self.outputs.append(outs)
            
            time.sleep(1000)
            # check crash, counterexample and seed.
            # if constant.ERROR in outs:
            if self.sut.target_process_exception():
                self.save_crash()
                
            self.dfa_step(fuzzed_abs, outs, abstract_sequence)
            violation_names = self.stateChecker.check_violation_for_all_DFAs(self.inputs, self.outputs)
            self.ltl_violation_count += len(violation_names)
            [self.save_byte_and_pcap(f'{self.out_dir}/{file_name}') for file_name in violation_names]
            
            seed_name = self.stateChecker.check_is_interesting(self.inputs, self.outputs)
            if seed_name:
                self.save_byte_and_pcap(f'{self.out_dir}/{seed_name}')
            
        print(f'fuzzed query: {self.inputs}\n{self.outputs}')
        print(f'{abstract_sequence}')
        self.total_fuzz_count += 1
        self.sut.post()
          
    def fuzz_one_seed(self, fuzz_times, dfa:LTLfDfa, seed:Seed):
        print('*'*100)
        print(f'current DFA: {self.stateChecker.current_dfa}')
        print(f'Current seed to fuzz: {seed.inputs}')
        for t in range(fuzz_times):
            print('-'*50)
            print(f'total fuzz count: {self.total_fuzz_count}')
            print(f'current seed fuzz count : {t}')
            self.sut.pre()
            self.reset_sut_and_dfa()
            self.load_fuzz_data_from_file(f'{self.out_dir}/{dfa.formula_name}/{seed.name}')
            abstract_sequence = []
            # replay the seed
            for i in range(len(seed.inputs)):
                self.inputs.append(seed.inputs[i])
                fuzzed_abs, outs = self.sut.replay_fuzz_step(seed.inputs[i])
                outs = outs.split('-')
                self.outputs.append(outs)
                self.dfa_step(seed.inputs[i], outs, abstract_sequence)
            
            # choose and execute suffix
            suffix_len = random.randint(0, self.fuzzing_walk_len-len(seed.inputs)) if self.fuzzing_walk_len-len(seed.inputs)>0 else constant.MIN_SUFFIX_LENGTH
            for i in range(suffix_len):
                next_symbol = self.stateChecker.get_next_input()
                if next_symbol is None:
                    print('target state is unreachable')
                    break
                elif next_symbol == 'random':
                    next_symbol = random.choice(self.alphabet)
                fuzzed_abs, outs = self.sut.fuzz_step(next_symbol)
                self.inputs.append(fuzzed_abs)
                outs = outs.split('-')
                self.outputs.append(outs)
                
                # check crash, counterexample and seed.
                # if constant.ERROR in outs:
                if self.sut.target_process_exception():
                    self.save_crash()
                    
                self.dfa_step(fuzzed_abs, outs, abstract_sequence)
                violation_names = self.stateChecker.check_violation_for_all_DFAs(self.inputs, self.outputs)
                self.ltl_violation_count += len(violation_names)
                [self.save_byte_and_pcap(f'{self.out_dir}/{file_name}') for file_name in violation_names]
            
                seed_name = self.stateChecker.check_is_interesting(self.inputs, self.outputs)
                if seed_name:
                    self.save_byte_and_pcap(f'{self.out_dir}/{seed_name}')
                
            print(f'{t}th fuzzed query: {self.inputs}\n{self.outputs}')
            print(f'{abstract_sequence}')
            self.total_fuzz_count += 1
            self.sut.post()
        
    def fuzzing(self, fuzzing_time):
        self.start_time = time.time()
        while True:
            dfa = self.stateChecker.choose_one_dfa()
            seed = self.stateChecker.choose_seed()
            if seed is None or random.randint(0, 4) == 0 or self.total_fuzz_count < 1000:
                self.fuzz_randomly()
            else:
                energy = seed.compute_energy()
                dfa.fuzzs += energy
                self.fuzz_one_seed(min(energy, constant.MAX_FUZZING_SEED_TIMES), dfa, seed)
            if time.time() - self.start_time + self.already_fuzz_time >= fuzzing_time:
                break
        self.generate_fuzz_report()
        print("Fuzz over, have a nice day!")
        
    def replay(self, name):
        self.sut.pre()
        self.reset_sut_and_dfa()
        self.load_fuzz_data_from_file(name)
        with open(f'{name}.txt', 'r') as f:
            lines = f.readlines()
        path = str2list(lines[1].strip('\n'))
        abstract_sequence = []
        for i in range(len(path)):
            self.inputs.append(path[i])
            _, outs = self.sut.replay_fuzz_step(path[i])
            outs = outs.split('-')
            self.outputs.append(outs)
            self.dfa_step(path[i], outs, abstract_sequence)
            violation_names = self.stateChecker.check_violation_for_all_DFAs(self.inputs, self.outputs)
            if violation_names:
                print(f'Found counterexample! {violation_names}')    
                     
        print(f'fuzzed query: {self.inputs}\n{self.outputs}')
        print(f'{abstract_sequence}')
        self.sut.post()

    def generate_fuzz_report(self):
        print("Generating fuzz report...")
        fuzzing_overall_report = ''
        fuzzing_overall_report += f'total fuzz time: {time.time()-self.start_time}\n'
        fuzzing_overall_report += f'total exections: {self.total_fuzz_count}\n'
        fuzzing_overall_report += f'total crash count: {self.crash_count}\n'
        fuzzing_overall_report += f'counterexample count: {self.ltl_violation_count}\n'
        fuzzing_overall_report += f'response type count: {len(self.sut.response_type_count)}\n{self.sut.response_type_count}\n'
        fuzzing_overall_report += self.stateChecker.generate_overall_report()
        print(fuzzing_overall_report)
        
    def save_before_terminated(self, signum, frame):
        print("Aborted by user.")
        self.generate_fuzz_report()
        
        print("Saving fuzz context...")
        fuzzer = ET.Element("fuzzer")
        self.already_fuzz_time += time.time()-self.start_time
        ET.SubElement(fuzzer, "fuzz_time").text = str(self.already_fuzz_time)
        ET.SubElement(fuzzer, "exections").text = str(self.total_fuzz_count)
        ET.SubElement(fuzzer, "crash_count").text = str(self.crash_count)
        ET.SubElement(fuzzer, "counterexample_count").text = str(self.ltl_violation_count)
        checker = ET.SubElement(fuzzer, "state_checker")
        self.stateChecker.save_dfa_context(checker)
        
        xml_content = ET.tostring(fuzzer, encoding='utf-8')
        dom = xml.dom.minidom.parseString(xml_content)
        pretty_xml = dom.toprettyxml()
        with open(f'{self.out_dir}/fuzz_context.xml', 'w') as f:
            f.write(pretty_xml)
            
        print("Completed!\nHave a nice day!\n")
        sys.exit(0)
        
    def resume(self):
        print(f'Resuming fuzz context from file {self.out_dir}/fuzz_context.xml...')
        tree = ET.parse(f'{self.out_dir}/fuzz_context.xml')
        fuzzer = tree.getroot()
        self.already_fuzz_time = float(fuzzer.find('fuzz_time').text)
        self.total_fuzz_count = int(fuzzer.find('exections').text)
        self.crash_count = int(fuzzer.find('crash_count').text)
        self.ltl_violation_count = int(fuzzer.find('counterexample_count').text)
        checker = fuzzer.find('state_checker')
        self.stateChecker.resume(checker)
        print('Resume completed! Fuzz will continue!')
