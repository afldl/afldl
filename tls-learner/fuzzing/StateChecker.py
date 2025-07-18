from LTLf.LTLfDfa import *
import shutil

class StateChecker():
    """
    Maintain all DFAs corresponding to every LTLf formula.
    """
    def __init__(self, formulas: dict , out_dir = None) -> None:
        """
        Args:
            formulas (dict): the LTLf formulas provided by tester.
            out_dir (_type_, optional): the folder to save all useful results.
        """
        self.out_dir = out_dir
        self.DFAs: Dict[str, LTLfDfa] = {}
        self.load_all_DFAs(formulas)
        self.current_dfa = random.choice(list(self.DFAs.keys()))
    
    def load_all_DFAs(self, formulas: dict):
        """
        Load all LTLf formulas and transform to DFAs.
        """
        print('loading all LTLf formulas and transform to DFAs...')
        for key in formulas.keys():
            self.DFAs[key] = ltl_formula_to_ltl_dfa(key, formulas[key]) 
            
    
    def reset_all_DFAs(self):
        [dfa.reset() for dfa in self.DFAs.values()]
    
    def step(self, inp: str, outs: List[str]):
        [dfa.step_based_on_inp_out(inp, outs) for dfa in self.DFAs.values()]

    def check_is_interesting(self, inputs, outputs):
        """
        Check whether current sequence is interesting for current DFA.
        If is, save the sequence to file.
        """
        dfa = self.DFAs[self.current_dfa]
        if dfa.found_interesting_sequence(inputs):
            file_name = f'{dfa.formula_name}/seed-{len(dfa.seeds_pool)}'
            save_to_file = f'{dfa.state_path}\n{inputs}\n{outputs}'
            self.save_sequence_to_file(file_name, save_to_file)
            return file_name
        return None
        
    def check_violation_for_all_DFAs(self, inputs, outputs):
        """
        Check whether current sequence reaches the accepted state for any DFAs.
        If is, save the sequence to file.
        """
        violations = []
        for dfa in self.DFAs.values():
            if dfa.reach_accepted_state():
                file_name = f'{dfa.formula_name}/ltl-{dfa.ltl_violation_count}'
                save_to_file = f'{dfa.state_path}\n{inputs}\n{outputs}'
                self.save_sequence_to_file(file_name, save_to_file)
                violations.append(file_name)
                
        return violations
    
    def choose_one_dfa(self):
        """Choose one DFA for next round fuzz based on score of all DFAs."""
        calculate_score = 0
        for dfa in self.DFAs.values():
            calculate_score += dfa.compute_score()
        rand = random.randint(0, math.ceil(calculate_score))
        calculate_score = 0
        for name, dfa in self.DFAs.items():
            calculate_score += dfa.score
            if calculate_score >= rand:
                self.current_dfa = name
                self.DFAs[self.current_dfa].selected_times += 1
                return self.DFAs[self.current_dfa]

    def choose_seed(self):
        return self.DFAs[self.current_dfa].choose_seed()
        
    def get_next_input(self):
        return self.DFAs[self.current_dfa].get_next_input()
    
    def save_sequence_to_file(self, file_name, content):    
        with open(f'{self.out_dir}/{file_name}.txt', 'w') as file:
            file.write(f'{content}')
            
    def generate_overall_report(self):
        report = '+'*100 + '\n'
        for f, dfa in self.DFAs.items():
            report += f'{f} : {dfa.formula}\n'
            report += f'selected times : {dfa.selected_times}\n'
            report += f'fuzz times : {dfa.fuzzs}\n' 
            report += f'LTLf violation count : {dfa.ltl_violation_count}\n'
            report += f'crash count : {dfa.crash_count}\n'
            report += f'seed pool size : {len(dfa.seeds_pool)}\n'
        return report
    
    def save_dfa_context(self, checker_et: ET.Element):
        ET.SubElement(checker_et, "current_dfa").text = str(self.current_dfa)
        for name, dfa in self.DFAs.items():
            label = ET.SubElement(checker_et, name)
            dfa.save_context(label)
            
    def resume(self, checker_et: ET.Element):
        self.current_dfa = checker_et.find('current_dfa').text
        for name, dfa in self.DFAs.items():
            et = checker_et.find(name)
            dfa.resume(et)
        
        