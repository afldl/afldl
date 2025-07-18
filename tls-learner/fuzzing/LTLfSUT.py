from abc import abstractmethod
from aalpy.base import SUL

class LTLfSUT(SUL):
    def __init__(self):
        super().__init__()
        self.response_type_count = []
    
    @abstractmethod
    def reset(self):
        pass

    @abstractmethod
    def step(self, letter:str):
        pass
    
    @abstractmethod
    def fuzz_step(self, letter:str):
        pass
    
    @abstractmethod
    def replay_fuzz_step(self, letter:str):
        pass
    
    @abstractmethod
    def save_pcap(self, name): 
        pass
    
    @abstractmethod
    def save_fuzz_contents(self, name): 
        pass
    
    @abstractmethod 
    def read_fuzz_contents(self, name):
        pass
    
    @abstractmethod 
    def sut_to_ltl_map(self, symbol, is_request):
        pass
    
    @abstractmethod 
    def ltl_to_sut_map(self, symbol_name):
        pass
    
    @abstractmethod 
    def target_process_exception(self):
        pass

        

